"""Windows only: the pipe transport against a pipe that this test process serves itself.

The pipe is local (`PIPE_REJECT_REMOTE_CLIENTS`), single-instance and owner-only, like the
runtime's. A pipe served by another account needs a second Windows account and is not
covered here.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from pathlib import Path
import secrets
import struct
import sys
import threading
import time
import unittest

# Isolated mode removes the example and test directories from the default import path.
sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
import reference_wrapper_windows as windows  # noqa: E402
from reference_wrapper import Client, Disconnected, ProtocolError, open_pipe  # noqa: E402
from test_reference_wrapper import ENVIRONMENT, closed, hello, receive, respond  # noqa: E402


PIPE_ACCESS_DUPLEX, FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00000003, 0x00080000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008  # With the byte type, byte read mode and blocking waits (all 0).
SDDL_REVISION_1 = 1
ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED, ERROR_PIPE_CONNECTED = 109, 232, 233, 535
CLIENT_GONE = (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED)
HANDLE, DWORD, BOOL, POINTER = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.POINTER


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", BOOL)]


def declared(library, name, restype, *argtypes):
    function = getattr(ctypes.WinDLL(library, use_last_error=True), name)
    function.restype, function.argtypes = restype, argtypes
    return function


def failed(call):
    return OSError(f"{call} failed (Windows error {ctypes.get_last_error()})")


def sid_text(sid):
    """The `S-1-...` form of a binary SID."""
    authority = int.from_bytes(sid[2:8], "big")
    return "-".join(map(str, ("S", sid[0], authority, *struct.unpack_from(f"<{sid[1]}I", sid, 8))))


class PipeServer:
    """One pipe instance and the thread that runs `script` on it with blocking I/O."""

    def __init__(self, script):
        transfer = (BOOL, HANDLE, ctypes.c_void_p, DWORD, POINTER(DWORD), ctypes.c_void_p)
        self._connect = declared("kernel32", "ConnectNamedPipe", BOOL, HANDLE, ctypes.c_void_p)
        self._read = declared("kernel32", "ReadFile", *transfer)
        self._write = declared("kernel32", "WriteFile", *transfer)
        self._cancel = declared("kernel32", "CancelIoEx", BOOL, HANDLE, ctypes.c_void_p)
        self._close = declared("kernel32", "CloseHandle", BOOL, HANDLE)
        self.name = "\\\\.\\pipe\\heimdall-" + secrets.token_hex(8) + "-control"
        self.errors = []
        self._handle = self._create()
        self._thread = threading.Thread(target=self._serve, args=(script,), daemon=True)
        self._thread.start()

    def _create(self):
        to_descriptor = declared("advapi32", "ConvertStringSecurityDescriptorToSecurityDescriptorW", BOOL,
                                 ctypes.c_wchar_p, DWORD, POINTER(ctypes.c_void_p), ctypes.c_void_p)
        local_free = declared("kernel32", "LocalFree", ctypes.c_void_p, ctypes.c_void_p)
        create = declared("kernel32", "CreateNamedPipeW", HANDLE, ctypes.c_wchar_p, DWORD, DWORD, DWORD,
                          DWORD, DWORD, DWORD, POINTER(SECURITY_ATTRIBUTES))
        owner, descriptor = sid_text(windows.Win32().caller_sid()), ctypes.c_void_p()
        # Owned by this user, and open to this user only.
        if not to_descriptor(f"O:{owner}D:P(A;;GA;;;{owner})", SDDL_REVISION_1, ctypes.byref(descriptor), None):
            raise failed("ConvertStringSecurityDescriptorToSecurityDescriptorW")
        try:
            attributes = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), descriptor.value, False)
            handle = create(self.name, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_REJECT_REMOTE_CLIENTS, 1, 65536, 65536, 0, ctypes.byref(attributes))
            if handle in (None, windows.INVALID_HANDLE):
                raise failed("CreateNamedPipeW")
            return handle
        finally:
            local_free(descriptor)

    def _serve(self, script):
        try:
            if not self._connect(self._handle, None):
                if ctypes.get_last_error() not in (ERROR_PIPE_CONNECTED, ERROR_NO_DATA):
                    raise failed("ConnectNamedPipe")
            script(self)
        except BaseException as error:
            self.errors.append(error)

    def recv(self, size):
        buffer, count = ctypes.create_string_buffer(size), DWORD(0)
        if not self._read(self._handle, buffer, size, ctypes.byref(count), None):
            if ctypes.get_last_error() in CLIENT_GONE:
                return b""
            raise failed("ReadFile")
        return buffer.raw[:count.value]

    def sendall(self, data):
        data, count = bytes(data), DWORD(0)
        while data:
            if not self._write(self._handle, data, len(data), ctypes.byref(count), None):
                raise failed("WriteFile")
            data = data[count.value:]

    def finish(self):
        self._thread.join(5)
        if self._thread.is_alive():
            self._cancel(self._handle, None)  # The script still waits on a client that has gone.
            self._thread.join(5)
        if self._thread.is_alive():
            self.errors.append(RuntimeError("the pipe server thread did not stop"))
        else:
            self._close(self._handle)


@contextmanager
def serving(script):
    server = PipeServer(script)
    try:
        yield server.name
    finally:
        server.finish()
    if server.errors:
        raise server.errors[0]


@unittest.skipUnless(sys.platform == "win32", "requires Windows named pipes")
class NativePipeTests(unittest.TestCase):
    def test_client_talks_to_a_pipe_this_user_owns_and_serves(self):
        requests = []

        def script(conn):
            hello(conn)
            requests.append(receive(conn))
            respond(conn, requests[0], data={"items": []})
            closed(conn)

        with serving(script) as endpoint:
            with Client(endpoint, ENVIRONMENT, timeout=5) as client:
                # Larger than the pipe's buffer, so the write waits on the reader.
                result = client.request("inspect", subject="destinations", padding="x" * 200000)
                self.assertEqual(result["data"]["items"], [])
        self.assertEqual(len(requests[0]["request"]["padding"]), 200000)

    def test_silent_server_times_out_the_read_and_ends_the_connection(self):
        def script(conn):
            hello(conn)
            receive(conn)
            closed(conn)  # It never answers, and sees the client leave.

        with serving(script) as endpoint:
            with Client(endpoint, ENVIRONMENT, timeout=0.5) as client:
                started = time.monotonic()
                with self.assertRaises(Disconnected):
                    client.request("inspect", subject="destinations")
                elapsed = time.monotonic() - started
        self.assertTrue(0.4 <= elapsed < 4, elapsed)

    def test_real_paths_normalize_and_a_missing_pipe_is_refused(self):
        api = windows.Win32()
        for path in ("//./pipe/heimdall-x-control", "\\\\.\\pipe\\a\\..\\heimdall-x-control"):
            with self.subTest(path=path):
                self.assertEqual(windows.pipe_path(path, api.full_path), "\\\\.\\pipe\\heimdall-x-control")
        for path in ("\\\\.\\pipe\\..\\C:\\Windows\\win.ini", "\\\\?\\pipe\\..\\heimdall-x-control",
                     "\\\\localhost\\pipe\\heimdall-x-control", "NUL", "heimdall-relative-control", "C:\\Windows",
                     "\\\\.\\pipe\\heimdall-x-signing"):
            with self.subTest(path=path), self.assertRaises(windows.PipeRefused):
                windows.pipe_path(path, api.full_path)
        with self.assertRaisesRegex(ProtocolError, "not found"):
            open_pipe("\\\\.\\pipe\\heimdall-absent-" + secrets.token_hex(8) + "-control", 1)


if __name__ == "__main__":
    unittest.main()
