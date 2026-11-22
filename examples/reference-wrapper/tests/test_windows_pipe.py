"""The Windows pipe checks and transport, driven by fakes on any platform."""

from __future__ import annotations

import ctypes
from functools import partial
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import types
import unittest

# Isolated mode removes the example directory from the default import path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import reference_wrapper_windows as windows  # noqa: E402
from reference_wrapper import CAPABILITIES, Client, Disconnected, ProtocolError, open_pipe  # noqa: E402


def sid(*subauthorities):
    """A binary SID under the NT authority."""
    return (struct.pack("<BB", 1, len(subauthorities)) + (5).to_bytes(6, "big")
            + struct.pack(f"<{len(subauthorities)}I", *subauthorities))


ENVIRONMENT = "fixture-environment"
PIPE = "\\\\.\\pipe\\heimdall-0123abcd-control"
CALLER, OTHER = sid(21, 1, 2, 3, 1001), sid(21, 1, 2, 3, 1002)
PID, FILE_TYPE_DISK, WAIT_TIMEOUT = 4242, 1, 258
ACCESS_DENIED, PIPE_BUSY, FILE_NOT_FOUND, BROKEN_PIPE = 5, 231, 2, 109
# GENERIC_READ | GENERIC_WRITE, no sharing, OPEN_EXISTING, and
# SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED.
OPEN_ARGUMENTS = (0xC0000000, 0, 3, 0x40110000)
# Each name below has the `heimdall-` start and the `-control` end, so it is refused for the
# reason its shape shows: the type, the namespace, the first component or a second component.
REFUSED_PATHS = [
    "", "a\0b", b"\\\\.\\pipe\\heimdall-x-control", "heimdall-relative-control", "C:\\Windows",
    "\\\\.\\pipe", "\\\\.\\pipe\\", "\\\\.\\pipe\\other-0123-control",
    "\\\\.\\pipe\\HEIMDALL-x-control", "\\\\.\\pipe\\heimdall-x\\nested-control",
    "\\\\.\\pipe\\..\\C:\\Windows\\win.ini", "\\\\?\\pipe\\..\\heimdall-x-control",
    "\\\\?\\pipe\\heimdall-x/../heimdall-y-control", "\\\\localhost\\pipe\\heimdall-x-control",
    "\\\\.\\GLOBALROOT\\Device\\NamedPipe\\heimdall-x-control",
]
# A wrapper opens the control pipe only: every other `heimdall-` name is refused, the runtime's
# signing and issuer pipes included.
NOT_CONTROL_PATHS = [
    "\\\\.\\pipe\\heimdall-", "\\\\.\\pipe\\heimdall-0123abcd", "\\\\.\\pipe\\heimdall-0123abcd-signing",
    "\\\\.\\pipe\\heimdall-0123abcd-issuer", "\\\\?\\pipe\\heimdall-0123abcd-signing",
    "\\\\.\\pipe\\heimdall-0123abcd-CONTROL", "\\\\.\\pipe\\heimdall-0123abcd-control-signing",
    # No token: the two affixes overlap on one hyphen.
    "\\\\.\\pipe\\heimdall-control", "\\\\.\\pipe\\heimdall--control",
]
ACCEPTED_PATHS = {
    PIPE: PIPE,
    "//./pipe/heimdall-x-control": "\\\\.\\pipe\\heimdall-x-control",
    "\\\\.\\PIPE\\heimdall-x-control": "\\\\.\\PIPE\\heimdall-x-control",
    "\\\\?\\pipe\\heimdall-x-control": "\\\\?\\pipe\\heimdall-x-control",
    "\\\\.\\pipe\\a\\..\\heimdall-x-control": "\\\\.\\pipe\\heimdall-x-control",
}


def normalize(path):
    """A stand-in for `GetFullPathNameW`, over the path shapes that
    `classify_path_namespace_rules` in `crates/ipc/src/windows.rs` lists."""
    if path.startswith("\\\\?\\"):
        return path  # Verbatim paths come back unchanged.
    path = path.replace("/", "\\")
    if not path.startswith("\\\\"):
        return "C:\\scratch\\" + path
    if not path.startswith("\\\\.\\"):
        return path
    parts = []
    for part in path[4:].split("\\"):
        if part == "..":
            del parts[-1:]
        elif part != ".":
            parts.append(part)
    return "\\\\.\\" + "\\".join(parts)


def frame(message):
    body = json.dumps(message).encode("utf-8")
    return struct.pack(">I", len(body)) + body


def frames(data):
    messages = []
    while data:
        size, = struct.unpack(">I", data[:4])
        messages.append(json.loads(data[4:4 + size]))
        data = data[4 + size:]
    return messages


SERVER_HELLO = frame({
    "type": "hello", "protocol": 1, "schema_version": "1",
    "environment_id": ENVIRONMENT, "capabilities": list(CAPABILITIES),
})


class FakeApi:
    """The adapter's surface with scripted facts. It offers no way to look up an account
    name, so only `equal_sid` on binary SIDs can decide a check."""

    HANDLE = 7

    def __init__(self, replies=b"", **facts):
        self.facts = {"type": windows.FILE_TYPE_PIPE, "owner": CALLER, "server": CALLER,
                      "equal": True, "open_errors": [], "take": 1 << 30, **facts}
        self.replies = replies
        self.calls, self.compared, self.written, self.timeouts, self.closed = [], [], [], [], []

    def _fact(self, name, handle=HANDLE):
        assert handle == self.HANDLE
        self.calls.append(name)
        if isinstance(self.facts[name], Exception):
            raise self.facts[name]
        return self.facts[name]

    def full_path(self, path):
        self.calls.append("full_path")
        return normalize(path)

    def caller_sid(self):
        self.calls.append("caller_sid")
        return CALLER

    def create_file(self, *arguments):
        self.calls.append("create_file")
        self.opened = arguments
        if self.facts["open_errors"]:
            raise windows.Win32Error("CreateFileW", self.facts["open_errors"].pop(0))
        return self.HANDLE

    def file_type(self, handle):
        return self._fact("type", handle)

    def owner_sid(self, handle):
        return self._fact("owner", handle)

    def server_pid(self, handle):
        assert handle == self.HANDLE
        self.calls.append("server_pid")
        return PID

    def process_sid(self, pid):
        assert pid == PID
        return self._fact("server")

    def equal_sid(self, first, second):
        self.compared.append((first, second))
        return self.facts["equal"] and first == second

    def write(self, handle, data, timeout):
        assert handle == self.HANDLE and isinstance(data, bytes)
        self.calls.append("write")
        self.written.append(data[:self.facts["take"]])
        return len(self.written[-1])

    def read(self, handle, size, timeout):
        assert handle == self.HANDLE
        self.calls.append("read")
        self.timeouts.append(timeout)
        if not self.replies and "read_error" in self.facts:
            raise self.facts["read_error"]
        chunk, self.replies = self.replies[:min(size, 3)], self.replies[min(size, 3):]  # Fragmented.
        return chunk

    def close(self, handle):
        self.calls.append("close")
        self.closed.append(handle)


class PipeCheckTests(unittest.TestCase):
    def test_other_namespaces_and_names_are_refused_before_any_open(self):
        for path in REFUSED_PATHS:
            with self.subTest(path=path):
                fake = FakeApi()
                with self.assertRaisesRegex(ProtocolError, "not a (local Heimdall )?named.pipe"):
                    Client(path, ENVIRONMENT, connector=partial(open_pipe, api=fake))
                self.assertLessEqual(set(fake.calls), {"full_path"})

    def test_names_other_than_the_control_pipe_are_refused_before_any_open(self):
        for path in NOT_CONTROL_PATHS:
            with self.subTest(path=path):
                fake = FakeApi()
                with self.assertRaisesRegex(ProtocolError, "not a Heimdall control pipe"):
                    Client(path, ENVIRONMENT, connector=partial(open_pipe, api=fake))
                self.assertEqual(fake.calls, ["full_path"])

    def test_the_normalized_path_is_opened_at_identification_level(self):
        for path, normalized in ACCEPTED_PATHS.items():
            with self.subTest(path=path):
                fake = FakeApi()
                open_pipe(path, 1, api=fake).close()
                self.assertEqual(fake.opened, (normalized,) + OPEN_ARGUMENTS)

    def test_each_failed_check_closes_the_handle_and_writes_nothing(self):
        opened = ["full_path", "caller_sid", "create_file", "type"]
        denied = windows.Win32Error("a query", ACCESS_DENIED)
        for facts, message, checked in [
            ({"type": FILE_TYPE_DISK}, "not a pipe", []),
            ({"owner": OTHER}, "not owned by the caller", ["owner"]),
            ({"owner": denied}, "could not be completed", ["owner"]),
            ({"server": OTHER}, "runs as another user", ["owner", "server_pid", "server"]),
            ({"server": denied}, "could not be completed", ["owner", "server_pid", "server"]),
        ]:
            with self.subTest(facts=facts):
                fake = FakeApi(**facts)
                with self.assertRaisesRegex(ProtocolError, message):
                    Client(PIPE, ENVIRONMENT, connector=partial(open_pipe, api=fake))
                self.assertEqual(fake.calls, opened + checked + ["close"])
                self.assertEqual((fake.closed, fake.written), ([FakeApi.HANDLE], []))

    def test_equal_sid_decides_on_binary_sids(self):
        fake = FakeApi(owner=bytes(CALLER), server=bytes(CALLER))
        open_pipe(PIPE, 1, api=fake).close()
        self.assertEqual(fake.compared, [(CALLER, CALLER), (CALLER, CALLER)])
        unequal = FakeApi(equal=False)  # Identical bytes do not pass without EqualSid's verdict.
        with self.assertRaisesRegex(ProtocolError, "not owned by the caller"):
            open_pipe(PIPE, 1, api=unequal)
        self.assertEqual((unequal.closed, unequal.written), ([FakeApi.HANDLE], []))

    def test_busy_pipe_is_retried_and_other_open_failures_refuse(self):
        fake, pauses = FakeApi(open_errors=[PIPE_BUSY, PIPE_BUSY]), []
        self.assertEqual(windows.open_handle(PIPE, fake.create_file, 1, sleep=pauses.append), FakeApi.HANDLE)
        self.assertEqual((fake.calls, pauses), (["create_file"] * 3, [windows.BUSY_BACKOFF] * 2))
        for errors, timeout, message in [([FILE_NOT_FOUND], 1, "not found"),
                                         ([ACCESS_DENIED], 1, "could not be opened"),
                                         ([PIPE_BUSY], 0, "could not be opened")]:
            with self.subTest(errors=errors):
                fake = FakeApi(open_errors=errors)
                with self.assertRaisesRegex(ProtocolError, message):
                    open_pipe(PIPE, timeout, api=fake)
                self.assertEqual((fake.calls.count("create_file"), fake.closed), (1, []))

    def test_client_speaks_only_after_every_check(self):
        reply = frame({"type": "response", "in_reply_to": 1, "envelope": {
            "schema_version": "1", "code": "OK", "data": {"items": []}}})
        fake = FakeApi(SERVER_HELLO + reply, take=50000, read_error=TimeoutError("timed out"))
        with Client(PIPE, ENVIRONMENT, timeout=7, connector=partial(open_pipe, api=fake)) as client:
            self.assertLess(fake.calls.index("server"), fake.calls.index("write"))
            result = client.request("inspect", subject="destinations", padding="x" * 100000)
            self.assertEqual(result["data"]["items"], [])
            hello, request = frames(b"".join(fake.written))
            self.assertEqual((hello["type"], request["request"]["op"]), ("hello", "inspect"))
            self.assertEqual(len(request["request"]["padding"]), 100000)
            self.assertLessEqual(max(map(len, fake.written)), 50000)
            self.assertEqual({5.0, 7}, set(fake.timeouts))  # The hello's bound, then the caller's.
            with self.assertRaises(Disconnected):  # A read timeout ends the connection.
                client.request("inspect", subject="destinations")
            with self.assertRaises(Disconnected):
                client.request("inspect", subject="destinations")
        self.assertEqual(fake.closed, [FakeApi.HANDLE])


class FakeKernel:
    """Python stand-ins for the declared Win32 functions. The adapter reaches them through
    real ctypes signatures, so its argument marshalling and pointer handling run here too."""

    def __init__(self):
        self.error, self.failures, self.handles, self.keep = 0, [], {}, []
        self.file_type, self.owner, self.server = windows.FILE_TYPE_PIPE, CALLER, CALLER
        self.denied = set()  # Functions that fail with access denied.
        self.compared, self.descriptors, self.freed, self.waits, self.written = [], [], [], [], []
        self.script, self.transfers, self.cancelled = [], {}, 0
        # Handles above 32 bits where pointers allow, so a truncating signature shows.
        self._next = 1 << (ctypes.sizeof(ctypes.c_void_p) * 8 - 2)

    def load(self, library):
        dll = types.SimpleNamespace()
        for name, (restype, argtypes) in windows.SIGNATURES[library].items():
            setattr(dll, name, ctypes.CFUNCTYPE(restype, *argtypes)(self._guarded(name)))
        return dll

    def _guarded(self, name):
        def call(*arguments):
            try:
                if name in self.denied:
                    return ACCESS_DENIED if name == "GetSecurityInfo" else self._fail(ACCESS_DENIED)
                return getattr(self, name)(*arguments)
            except BaseException as error:  # ctypes would only print it.
                self.failures.append((name, error))
                return 0
        return call

    def _fail(self, code, result=0):
        self.error = code
        return result

    def _handle(self, kind):
        self._next += 4
        self.handles[self._next] = kind
        return self._next

    def _block(self, data):
        self.keep.append(ctypes.create_string_buffer(data, len(data)))
        return ctypes.addressof(self.keep[-1])

    def GetFullPathNameW(self, path, size, buffer, part):
        full = normalize(path)
        if len(full) >= size:
            return len(full) + 1
        ctypes.memmove(buffer, ctypes.create_unicode_buffer(full), (len(full) + 1) * ctypes.sizeof(ctypes.c_wchar))
        return len(full)

    def CreateFileW(self, *arguments):
        self.opened = arguments
        return self._handle("pipe")

    def GetFileType(self, handle):
        return self.file_type if self.handles[handle] == "pipe" else 0

    def GetSecurityInfo(self, handle, kind, wanted, owner, group, dacl, sacl, descriptor):
        assert self.handles[handle] == "pipe" and not (group or dacl or sacl)
        assert (kind, wanted) == (windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
        owner[0] = descriptor[0] = self._block(self.owner)
        self.descriptors.append(descriptor[0])
        return 0

    def LocalFree(self, address):
        self.freed.append(address)

    def GetNamedPipeServerProcessId(self, handle, pid):
        assert self.handles[handle] == "pipe"
        pid[0] = PID
        return 1

    def GetCurrentProcess(self):
        return windows.INVALID_HANDLE

    def OpenProcess(self, access, inherit, pid):
        assert (access, inherit, pid) == (windows.PROCESS_QUERY_LIMITED_INFORMATION, 0, PID)
        return self._handle("process")

    def OpenProcessToken(self, process, access, token):
        assert access == windows.TOKEN_QUERY
        own = process == windows.INVALID_HANDLE
        assert own or self.handles[process] == "process"
        token[0] = self._handle("own token" if own else "server token")
        return 1

    def GetTokenInformation(self, token, kind, buffer, size, needed):
        user = CALLER if self.handles[token] == "own token" else self.server
        offset = 2 * ctypes.sizeof(ctypes.c_void_p)  # TOKEN_USER: the PSID, the attributes, then the SID.
        assert kind == windows.TOKEN_USER_CLASS and size >= offset + len(user)
        ctypes.c_void_p.from_address(buffer).value = buffer + offset
        ctypes.memmove(buffer + offset, user, len(user))
        needed[0] = offset + len(user)
        return 1

    def IsValidSid(self, address):
        return int(ctypes.string_at(address, 1) == b"\x01")

    def GetLengthSid(self, address):
        return 8 + 4 * ctypes.string_at(address, 2)[1]

    def EqualSid(self, first, second):
        pair = tuple(ctypes.string_at(address, self.GetLengthSid(address)) for address in (first, second))
        self.compared.append(pair)
        return int(pair[0] == pair[1])

    def CloseHandle(self, handle):
        del self.handles[handle]
        return 1

    def CreateEventW(self, security, manual, initial, name):
        assert manual and not initial and not security and name is None
        return self._handle("event")

    def _start(self, handle, done, overlapped, **transfer):
        assert self.handles[handle] == "pipe" and not done
        assert self.handles[overlapped.contents.hEvent] == "event"
        self.transfer = {"code": 0, "wait": windows.WAIT_OBJECT_0, "pending": False, "beats_cancel": False,
                         "cancelled": False, **transfer, **(self.script.pop(0) if self.script else {})}
        if self.transfer["code"] and not self.transfer["pending"]:
            return self._fail(self.transfer["code"])
        self.transfers[ctypes.addressof(overlapped.contents)] = self.transfer
        return self._fail(windows.ERROR_IO_PENDING) if self.transfer["pending"] else 1

    def ReadFile(self, handle, buffer, size, done, overlapped):
        result = self._start(handle, done, overlapped, data=b"", into=buffer)
        assert len(self.transfer["data"]) <= size
        return result

    def WriteFile(self, handle, buffer, size, done, overlapped):
        self.written.append(ctypes.string_at(buffer, size))
        return self._start(handle, done, overlapped, data=self.written[-1], into=None)

    def WaitForSingleObject(self, event, millis):
        assert self.handles[event] == "event"
        self.waits.append(millis)
        return self.transfer["wait"]

    def CancelIoEx(self, handle, overlapped):
        self.transfers[ctypes.addressof(overlapped.contents)]["cancelled"] = True
        self.cancelled += 1
        return 1

    def GetOverlappedResult(self, handle, overlapped, done, wait):
        transfer = self.transfers.pop(ctypes.addressof(overlapped.contents))
        assert wait
        if transfer["cancelled"] and not transfer["beats_cancel"]:
            return self._fail(windows.ERROR_OPERATION_ABORTED)
        if transfer["code"]:
            return self._fail(transfer["code"])
        if transfer["into"]:
            ctypes.memmove(transfer["into"], transfer["data"], len(transfer["data"]))
        done[0] = len(transfer["data"])
        return 1


class Win32AdapterTests(unittest.TestCase):
    def setUp(self):
        self.kernel = FakeKernel()
        self.api = windows.Win32(load=self.kernel.load, last_error=lambda: self.kernel.error)
        self.addCleanup(lambda kernel=self.kernel: self.assertEqual(kernel.failures, []))

    def test_checks_pass_through_the_declared_signatures_and_leak_nothing(self):
        link = open_pipe(PIPE, 1, api=self.api)
        self.assertEqual(self.kernel.opened, (PIPE, *OPEN_ARGUMENTS[:2], None, *OPEN_ARGUMENTS[2:], None))
        self.assertEqual(self.kernel.compared, [(CALLER, CALLER), (CALLER, CALLER)])
        self.assertEqual(self.kernel.freed, self.kernel.descriptors)
        self.assertEqual(list(self.kernel.handles.values()), ["pipe"])  # Tokens and the process are closed.
        link.close()
        link.close()
        self.assertEqual(self.kernel.handles, {})

    def test_each_failed_check_closes_every_handle_and_writes_nothing(self):
        for change, message in [
            ({"file_type": FILE_TYPE_DISK}, "not a pipe"),
            ({"owner": OTHER}, "not owned by the caller"),
            ({"server": OTHER}, "runs as another user"),
            ({"owner": b"\x02" + CALLER[1:]}, "could not be completed"),  # Not a valid SID.
            ({"denied": {"GetSecurityInfo"}}, "could not be completed"),
            ({"denied": {"GetNamedPipeServerProcessId"}}, "could not be completed"),
            ({"denied": {"OpenProcess"}}, "could not be completed"),
            ({"denied": {"OpenProcessToken"}}, "could not be completed"),
            ({"denied": {"GetTokenInformation"}}, "could not be completed"),
            ({"denied": {"CreateFileW"}}, "could not be opened"),
        ]:
            with self.subTest(change=change):
                self.setUp()
                vars(self.kernel).update(change)
                with self.assertRaisesRegex(ProtocolError, message):
                    Client(PIPE, ENVIRONMENT, connector=partial(open_pipe, api=self.api))
                self.assertEqual((self.kernel.handles, self.kernel.written), ({}, []))
                self.assertEqual(self.kernel.freed, self.kernel.descriptors)

    def test_full_path_grows_its_buffer_and_refuses_an_overlong_path(self):
        long_name = PIPE.replace("0123abcd", "x" * 300)
        self.assertEqual(windows.pipe_path(long_name, self.api.full_path), long_name)
        with self.assertRaisesRegex(windows.PipeRefused, "could not be normalized"):
            windows.pipe_path(PIPE.replace("0123abcd", "x" * windows.MAX_PATH_UNITS), self.api.full_path)

    def test_transfers_complete_time_out_and_always_settle(self):
        pipe = self.api.create_file(PIPE, *OPEN_ARGUMENTS)
        late = {"pending": True, "wait": WAIT_TIMEOUT}
        for script, timeout, expected in [
            ({"data": b"now"}, 1, b"now"),
            ({"data": b"later", "pending": True}, 1.5, b"later"),
            ({"data": b"raced", "beats_cancel": True, **late}, 0.25, b"raced"),
            ({"code": BROKEN_PIPE}, 1, b""),
            ({"code": BROKEN_PIPE, "pending": True}, None, b""),
            (late, 0.25, TimeoutError),
            ({"code": ACCESS_DENIED}, 1, windows.Win32Error),
        ]:
            with self.subTest(script=script):
                self.kernel.script = [script]
                if isinstance(expected, bytes):
                    self.assertEqual(self.api.read(pipe, 16, timeout), expected)
                else:
                    with self.assertRaises(expected):
                        self.api.read(pipe, 16, timeout)
                self.assertEqual((self.kernel.transfers, list(self.kernel.handles.values())), ({}, ["pipe"]))
        self.assertEqual(self.kernel.waits, [1500, 250, windows.INFINITE, 250])
        self.assertEqual(self.kernel.cancelled, 2)

        self.assertEqual(self.api.write(pipe, b"a\0b", 1), 3)  # Bytes are passed whole.
        self.kernel.script = [late]
        with self.assertRaises(TimeoutError):
            self.api.write(pipe, b"stuck", 0.25)
        self.assertEqual(self.kernel.written, [b"a\0b", b"stuck"])
        self.assertEqual((self.kernel.transfers, list(self.kernel.handles.values())), ({}, ["pipe"]))

    def test_an_interrupted_transfer_is_cancelled_before_its_buffer_is_released(self):
        def interrupted():
            raise KeyboardInterrupt

        pipe = self.api.create_file(PIPE, *OPEN_ARGUMENTS)
        self.kernel.script = [{"pending": True}]
        self.api._last_error = interrupted
        with self.assertRaises(KeyboardInterrupt):
            self.api.read(pipe, 16, 1)
        self.assertEqual((self.kernel.cancelled, self.kernel.transfers), (1, {}))
        self.assertEqual(list(self.kernel.handles.values()), ["pipe"])


# Runs in a fresh `python -I -B` with the wrapper's path as its argument. The transport must
# come from beside the wrapper, and must be the module whose refusal `open_pipe` translates.
LOADER_PROBE = """
import os, runpy, sys
wrapper, directory = sys.argv[1], os.path.dirname(sys.argv[1])
assert directory not in sys.path and "reference_wrapper_windows" not in sys.modules
{load}
class Api:
    def full_path(self, path):
        return path
try:
    names["open_pipe"]("C:\\\\outside-the-pipe-namespace", 1, api=Api())
except names["ProtocolError"] as error:
    transport = sys.modules["reference_wrapper_windows"]
    assert os.path.samefile(os.path.dirname(transport.__file__), directory)
    assert type(error.__cause__) is transport.PipeRefused
    print("refused by the transport beside the wrapper; its directory on sys.path:", directory in sys.path)
"""
LOADERS = {  # How the wrapper is loaded -> whether that leaves its directory on the import path.
    "sys.path.insert(0, directory); import reference_wrapper; names = vars(reference_wrapper)": True,  # README
    "names = runpy.run_path(wrapper)": False,
}


class IsolatedLoaderTests(unittest.TestCase):
    def test_isolated_python_finds_the_transport_beside_the_wrapper(self):
        wrapper = Path(__file__).resolve().parents[1] / "reference_wrapper.py"
        for load, on_path in LOADERS.items():
            with self.subTest(load=load), tempfile.TemporaryDirectory() as elsewhere:
                done = subprocess.run(
                    [sys.executable, "-I", "-B", "-c", LOADER_PROBE.format(load=load), str(wrapper)],
                    cwd=elsewhere, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
                self.assertEqual((done.returncode, done.stderr), (0, ""))
                self.assertEqual(done.stdout.split(":")[-1].strip(), str(on_path))


if __name__ == "__main__":
    unittest.main()
