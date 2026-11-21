"""Windows named-pipe transport for the reference wrapper (standard library and ctypes).

`open_pipe` checks the endpoint in this order and writes nothing until all pass:

1. after `GetFullPathNameW`, the path is `\\\\.\\pipe\\heimdall-...` or `\\\\?\\pipe\\heimdall-...`;
2. `CreateFileW` opens it at identification level, so the server can identify this
   client and can never act as it;
3. `GetFileType` says the handle is a pipe;
4. the pipe's owner SID is the caller's user SID;
5. the process serving the pipe runs as the caller's user SID.

SIDs are copied as binary SIDs and compared with `EqualSid`; account names are never
looked up. A call that fails is a refusal. Messages name no SID.

Reads and writes use overlapped I/O. At the link's timeout the transfer is cancelled
with `CancelIoEx`, and the call returns only after the cancellation has settled.
"""

from __future__ import annotations

import ctypes
import math
import os
import time


HANDLE, DWORD, BOOL = ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int
INVALID_HANDLE = ctypes.c_void_p(-1).value
GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING = 0x80000000, 0x40000000, 3
SECURITY_SQOS_PRESENT, SECURITY_IDENTIFICATION = 0x00100000, 0x00010000
FILE_FLAG_OVERLAPPED = 0x40000000
OPEN_FLAGS = SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | FILE_FLAG_OVERLAPPED
FILE_TYPE_PIPE = 3
SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION = 6, 0x00000001
PROCESS_QUERY_LIMITED_INFORMATION, TOKEN_QUERY, TOKEN_USER_CLASS = 0x1000, 0x0008, 1
TOKEN_USER_BYTES = 256  # TOKEN_USER is one pointer, one DWORD and a SID of at most 68 bytes.
ERROR_HANDLE_EOF, ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED = 38, 109, 233
ERROR_PIPE_BUSY, ERROR_OPERATION_ABORTED, ERROR_IO_PENDING, ERROR_INVALID_SID = 231, 995, 997, 1337
END_OF_PIPE = (ERROR_HANDLE_EOF, ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED)
WAIT_OBJECT_0, INFINITE = 0, 0xFFFFFFFF
MAX_PATH_UNITS = 32768
PIPE_PREFIXES = ("\\\\.\\pipe\\", "\\\\?\\pipe\\")
PIPE_NAME = "heimdall-"
BUSY_WAIT, BUSY_BACKOFF = 0.5, 0.025  # Seconds: the wait when no timeout is given, and the pause.
WRITE_CHUNK = READ_CHUNK = 65536


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
        ("Offset", DWORD), ("OffsetHigh", DWORD), ("hEvent", HANDLE),
    ]


_P_VOID, _P_DWORD, _P_OVERLAPPED = ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(DWORD), ctypes.POINTER(OVERLAPPED)
# library -> function -> (restype, argtypes). Every call below is declared here.
SIGNATURES = {
    "kernel32": {
        "GetFullPathNameW": (DWORD, (ctypes.c_wchar_p, DWORD, ctypes.c_wchar_p, ctypes.c_void_p)),
        "CreateFileW": (HANDLE, (ctypes.c_wchar_p, DWORD, DWORD, ctypes.c_void_p, DWORD, DWORD, HANDLE)),
        "GetFileType": (DWORD, (HANDLE,)),
        "GetNamedPipeServerProcessId": (BOOL, (HANDLE, _P_DWORD)),
        "GetCurrentProcess": (HANDLE, ()),
        "OpenProcess": (HANDLE, (DWORD, BOOL, DWORD)),
        "CloseHandle": (BOOL, (HANDLE,)),
        "LocalFree": (ctypes.c_void_p, (ctypes.c_void_p,)),
        "CreateEventW": (HANDLE, (ctypes.c_void_p, BOOL, BOOL, ctypes.c_wchar_p)),
        "WaitForSingleObject": (DWORD, (HANDLE, DWORD)),
        "ReadFile": (BOOL, (HANDLE, ctypes.c_void_p, DWORD, _P_DWORD, _P_OVERLAPPED)),
        "WriteFile": (BOOL, (HANDLE, ctypes.c_char_p, DWORD, _P_DWORD, _P_OVERLAPPED)),
        "GetOverlappedResult": (BOOL, (HANDLE, _P_OVERLAPPED, _P_DWORD, BOOL)),
        "CancelIoEx": (BOOL, (HANDLE, _P_OVERLAPPED)),
    },
    "advapi32": {
        "GetSecurityInfo": (DWORD, (HANDLE, ctypes.c_int, DWORD, _P_VOID, _P_VOID, _P_VOID, _P_VOID, _P_VOID)),
        "OpenProcessToken": (BOOL, (HANDLE, DWORD, _P_VOID)),
        "GetTokenInformation": (BOOL, (HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD, _P_DWORD)),
        "IsValidSid": (BOOL, (ctypes.c_void_p,)),
        "GetLengthSid": (DWORD, (ctypes.c_void_p,)),
        "EqualSid": (BOOL, (ctypes.c_char_p, ctypes.c_char_p)),
    },
}


class PipeRefused(Exception):
    """An endpoint check failed before any data was written."""


class Win32Error(OSError):
    """A failed Win32 call: its name and error code, never an argument."""

    def __init__(self, call, code):
        super().__init__(f"{call} failed (Windows error {code})")
        self.call, self.code = call, code


class Win32:
    """The Win32 calls the checks and the link need, each with a declared signature."""

    def __init__(self, load=None, last_error=None):
        load = load or (lambda name: ctypes.WinDLL(name, use_last_error=True))
        self._last_error = last_error or ctypes.get_last_error
        for library, functions in SIGNATURES.items():
            dll = load(library)
            for name, (restype, argtypes) in functions.items():
                function = getattr(dll, name)
                function.restype, function.argtypes = restype, argtypes
                setattr(self, "_" + name, function)

    def _failed(self, call):
        return Win32Error(call, self._last_error())

    def full_path(self, path):
        """`GetFullPathNameW`: string normalization only; it opens nothing."""
        for size in (260, MAX_PATH_UNITS):
            buffer = ctypes.create_unicode_buffer(size)
            written = self._GetFullPathNameW(path, size, buffer, None)
            if 0 < written < size:
                return buffer[:written]
            if written == 0:
                break
        raise self._failed("GetFullPathNameW")

    def create_file(self, path, access, share, disposition, flags):
        handle = self._CreateFileW(path, access, share, None, disposition, flags, None)
        if handle in (None, INVALID_HANDLE):
            raise self._failed("CreateFileW")
        return handle

    def file_type(self, handle):
        return self._GetFileType(handle)

    def close(self, handle):
        self._CloseHandle(handle)

    def _sid(self, address):
        """Copy a valid SID out of memory that another call owns."""
        if not address or not self._IsValidSid(address):
            raise Win32Error("IsValidSid", ERROR_INVALID_SID)
        return ctypes.string_at(address, self._GetLengthSid(address))

    def owner_sid(self, handle):
        """The owner SID of the object behind an open handle (needs `READ_CONTROL`)."""
        owner, descriptor = ctypes.c_void_p(), ctypes.c_void_p()
        code = self._GetSecurityInfo(handle, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                                     ctypes.byref(owner), None, None, None, ctypes.byref(descriptor))
        if code:
            raise Win32Error("GetSecurityInfo", code)
        try:
            return self._sid(owner.value)
        finally:
            self._LocalFree(descriptor)

    def server_pid(self, handle):
        pid = DWORD(0)
        if not self._GetNamedPipeServerProcessId(handle, ctypes.byref(pid)):
            raise self._failed("GetNamedPipeServerProcessId")
        return pid.value

    def _token_user(self, process):
        token = ctypes.c_void_p()
        if not self._OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
            raise self._failed("OpenProcessToken")
        try:
            buffer, needed = ctypes.create_string_buffer(TOKEN_USER_BYTES), DWORD(0)
            if not self._GetTokenInformation(token, TOKEN_USER_CLASS, buffer, len(buffer), ctypes.byref(needed)):
                raise self._failed("GetTokenInformation")
            # TOKEN_USER begins with the PSID, which points into the same buffer.
            return self._sid(ctypes.cast(buffer, _P_VOID)[0])
        finally:
            self._CloseHandle(token)

    def caller_sid(self):
        """This process's user SID. `GetCurrentProcess` is a pseudo-handle and is not closed."""
        return self._token_user(self._GetCurrentProcess())

    def process_sid(self, pid):
        """The user SID that process `pid` runs as."""
        process = self._OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not process:
            raise self._failed("OpenProcess")
        try:
            return self._token_user(process)
        finally:
            self._CloseHandle(process)

    def equal_sid(self, first, second):
        return bool(self._EqualSid(first, second))

    def _transfer(self, handle, timeout, call, start):
        """Run one overlapped transfer and return its byte count, or cancel it at the timeout."""
        event = self._CreateEventW(None, True, False, None)
        if not event:
            raise self._failed("CreateEventW")
        try:
            overlapped, done = OVERLAPPED(hEvent=event), DWORD(0)
            reference = ctypes.byref(overlapped)
            if not start(reference):
                code = self._last_error()
                if code != ERROR_IO_PENDING:
                    raise Win32Error(call, code)
                millis = INFINITE if timeout is None else min(math.ceil(max(timeout, 0) * 1000), INFINITE - 1)
                if self._WaitForSingleObject(event, millis) != WAIT_OBJECT_0:
                    self._CancelIoEx(handle, reference)
                    # The kernel owns the buffer and the OVERLAPPED until the transfer settles.
                    if self._GetOverlappedResult(handle, reference, ctypes.byref(done), True):
                        return done.value  # It finished before the cancellation landed.
                    code = self._last_error()
                    if code == ERROR_OPERATION_ABORTED:
                        raise TimeoutError("named-pipe transfer timed out")
                    raise Win32Error(call, code)
            if not self._GetOverlappedResult(handle, reference, ctypes.byref(done), False):
                raise self._failed(call)
            return done.value
        finally:
            self._CloseHandle(event)

    def read(self, handle, size, timeout):
        """Up to `size` bytes; `b""` when the server has closed its end."""
        buffer = ctypes.create_string_buffer(size)
        try:
            count = self._transfer(handle, timeout, "ReadFile",
                                   lambda overlapped: self._ReadFile(handle, buffer, size, None, overlapped))
        except Win32Error as error:
            if error.code in END_OF_PIPE:
                return b""
            raise
        return buffer.raw[:count]

    def write(self, handle, data, timeout):
        return self._transfer(handle, timeout, "WriteFile",
                              lambda overlapped: self._WriteFile(handle, data, len(data), None, overlapped))


def pipe_path(endpoint, full_path):
    """Normalize, then require a local `heimdall-` pipe name. Opens nothing."""
    text = os.fspath(endpoint)
    if not isinstance(text, str) or not text or "\0" in text:
        raise PipeRefused("endpoint is not a named-pipe path")
    try:
        full = full_path(text)
    except OSError as error:
        raise PipeRefused("endpoint path could not be normalized") from error
    prefix = next((p for p in PIPE_PREFIXES if full[:len(p)].lower() == p), None)
    name = full[len(prefix):] if prefix else ""
    if len(name) <= len(PIPE_NAME) or not name.startswith(PIPE_NAME) or "\\" in name or "/" in name:
        raise PipeRefused("endpoint is not a local Heimdall named pipe")
    return full


def open_handle(path, create_file, timeout, *, sleep=time.sleep):
    """Open the normalized path at identification level, retrying only a busy pipe."""
    deadline = time.monotonic() + (BUSY_WAIT if timeout is None else timeout)
    while True:
        try:
            return create_file(path, GENERIC_READ | GENERIC_WRITE, 0, OPEN_EXISTING, OPEN_FLAGS)
        except OSError as error:
            if getattr(error, "code", None) != ERROR_PIPE_BUSY or time.monotonic() >= deadline:
                raise PipeRefused("named pipe could not be opened") from error
        sleep(BUSY_BACKOFF)


def require_pipe(handle, file_type):
    if file_type(handle) != FILE_TYPE_PIPE:
        raise PipeRefused("endpoint handle is not a pipe")


def require_owner(handle, caller, owner_sid, equal_sid):
    """The pipe's owner SID must be the caller's user SID."""
    if not equal_sid(owner_sid(handle), caller):
        raise PipeRefused("named pipe is not owned by the caller")


def require_server(handle, caller, server_pid, process_sid, equal_sid):
    """The process serving this pipe must run as the caller's user SID."""
    if not equal_sid(process_sid(server_pid(handle)), caller):
        raise PipeRefused("named-pipe server runs as another user")


class PipeLink:
    """The socket subset the client uses, over one overlapped pipe handle."""

    def __init__(self, handle, api, timeout):
        self._handle, self._api, self._timeout = handle, api, timeout

    def _open(self):
        if self._handle is None:
            raise OSError("named pipe is closed")
        return self._handle

    def settimeout(self, timeout):
        self._timeout = timeout

    def sendall(self, data):
        """Write everything within one timeout, as `socket.sendall` does."""
        deadline = None if self._timeout is None else time.monotonic() + self._timeout
        view = memoryview(data)
        while view:
            left = None if deadline is None else deadline - time.monotonic()
            if left is not None and left <= 0:
                raise TimeoutError("named-pipe write timed out")
            sent = self._api.write(self._open(), bytes(view[:WRITE_CHUNK]), left)
            if not sent:
                raise OSError("named pipe accepted no data")
            view = view[sent:]

    def recv(self, size):
        return self._api.read(self._open(), min(size, READ_CHUNK), self._timeout)

    def close(self):
        handle, self._handle = self._handle, None
        if handle is not None:
            self._api.close(handle)


def open_pipe(endpoint, timeout, *, api=None):
    """Return a connected link, or raise `PipeRefused` with the handle closed and nothing written."""
    api = api or Win32()
    path = pipe_path(endpoint, api.full_path)
    handle = None
    try:
        caller = api.caller_sid()
        handle = open_handle(path, api.create_file, timeout)
        require_pipe(handle, api.file_type)
        require_owner(handle, caller, api.owner_sid, api.equal_sid)
        require_server(handle, caller, api.server_pid, api.process_sid, api.equal_sid)
    except BaseException as error:
        if handle is not None:
            api.close(handle)
        if isinstance(error, OSError):
            raise PipeRefused("named-pipe endpoint check could not be completed") from error
        raise
    return PipeLink(handle, api, timeout)
