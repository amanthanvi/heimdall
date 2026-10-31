use crate::{J, wide};
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, RevertToSelf, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenImpersonationLevel, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX, SECURITY_ANONYMOUS, SECURITY_IDENTIFICATION,
    SECURITY_IMPERSONATION,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, ImpersonateNamedPipeClient,
    PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

fn redact(s: &str) -> String {
    // never write machine/user-unique SID bodies to evidence
    match s.strip_prefix("S-1-5-21-") {
        Some(_) => format!("S-1-5-21-<redacted>-{}", s.rsplit('-').next().unwrap_or("")),
        None => s.to_string(),
    }
}

/// SID of the user in `token`, as a string.
fn token_user_sid(token: HANDLE) -> Result<String, String> {
    let mut n = 0u32;
    // SAFETY: two-call size/fill; buffer is u64-backed so TOKEN_USER is correctly aligned.
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut n);
        let mut buf = vec![0u64; (n as usize).div_ceil(8).max(1)];
        if GetTokenInformation(token, TokenUser, buf.as_mut_ptr() as *mut c_void, n, &mut n) == 0 {
            return Err(format!("GetTokenInformation(user): {}", GetLastError()));
        }
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut w: *mut u16 = null_mut();
        if ConvertSidToStringSidW(tu.User.Sid, &mut w) == 0 {
            return Err(format!("ConvertSidToStringSidW: {}", GetLastError()));
        }
        let len = (0..).take_while(|&i| *w.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(w, len));
        LocalFree(w as _);
        Ok(s)
    }
}

fn own_sid() -> Result<String, String> {
    let mut t: HANDLE = null_mut();
    // SAFETY: out-pointer is a live local; the token is owned (closed) by OwnedHandle.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) == 0 {
            return Err(format!("OpenProcessToken: {}", GetLastError()));
        }
        let t = OwnedHandle::from_raw_handle(t);
        token_user_sid(t.as_raw_handle())
    }
}

/// Reverts impersonation on drop. A failed revert leaves the thread impersonating: abort (fail closed).
struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        // SAFETY: plain call.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

/// ImpersonateNamedPipeClient on this thread, read the thread token (SID, impersonation level), revert.
fn sid_by_impersonation(pipe: HANDLE) -> Result<(String, i32), String> {
    // SAFETY: Revert guard restores the thread identity on every exit path.
    unsafe {
        if ImpersonateNamedPipeClient(pipe) == 0 {
            return Err(format!("ImpersonateNamedPipeClient: {}", GetLastError()));
        }
        let _g = Revert;
        let mut t: HANDLE = null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut t) == 0 {
            return Err(format!("OpenThreadToken: {}", GetLastError()));
        }
        let t = OwnedHandle::from_raw_handle(t);
        let mut level = 0i32;
        let mut n = 0u32;
        if GetTokenInformation(
            t.as_raw_handle(),
            TokenImpersonationLevel,
            &mut level as *mut i32 as *mut c_void,
            4,
            &mut n,
        ) == 0
        {
            return Err(format!("GetTokenInformation(level): {}", GetLastError()));
        }
        Ok((token_user_sid(t.as_raw_handle())?, level))
    }
}

fn sid_by_pid(pipe: HANDLE) -> Result<String, String> {
    // SAFETY: handles are owned by OwnedHandle.
    unsafe {
        let mut pid = 0u32;
        if GetNamedPipeClientProcessId(pipe, &mut pid) == 0 {
            return Err(format!("GetNamedPipeClientProcessId: {}", GetLastError()));
        }
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if p.is_null() {
            return Err(format!("OpenProcess: {}", GetLastError()));
        }
        let p = OwnedHandle::from_raw_handle(p);
        let mut t: HANDLE = null_mut();
        if OpenProcessToken(p.as_raw_handle(), TOKEN_QUERY, &mut t) == 0 {
            return Err(format!("OpenProcessToken: {}", GetLastError()));
        }
        let t = OwnedHandle::from_raw_handle(t);
        token_user_sid(t.as_raw_handle())
    }
}

fn create_instance(name: &str, first: bool, sa: &SECURITY_ATTRIBUTES) -> Result<HANDLE, u32> {
    let n = wide(&format!(r"\\.\pipe\{name}"));
    let open = PIPE_ACCESS_DUPLEX
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    // SAFETY: `sa` and its descriptor outlive the call.
    let h = unsafe {
        CreateNamedPipeW(
            n.as_ptr(),
            open,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            4096,
            4096,
            0,
            sa,
        )
    };
    if h == INVALID_HANDLE_VALUE {
        Err(unsafe { GetLastError() })
    } else {
        Ok(h)
    }
}

fn serve(pipe: usize, want: &str) {
    let h = pipe as HANDLE;
    let mut j = J::new();
    j.s("event", "conn");
    let accept = match sid_by_impersonation(h) {
        Ok((sid, level)) => {
            j.s("client_sid", &redact(&sid))
                .n("impersonation_level", level as i64);
            sid.eq_ignore_ascii_case(want)
        }
        Err(e) => {
            j.s("impersonation_error", &e);
            false
        }
    };
    match sid_by_pid(h) {
        Ok(s) => {
            j.b("pid_sid_matches_expected", s.eq_ignore_ascii_case(want));
        }
        Err(e) => {
            j.s("pid_check_error", &e);
        }
    }
    j.s("decision", if accept { "accept" } else { "refuse" })
        .emit();
    // SAFETY: we own the pipe handle; File closes it on drop.
    let f = unsafe { File::from_raw_handle(h) };
    let mut w = &f;
    if !accept {
        let _ = w.write_all(b"denied\n");
    } else {
        let _ = w.write_all(b"ok\n");
        let mut line = String::new();
        let _ = BufReader::new(&f).read_line(&mut line);
        let _ = w.write_all(format!("echo:{}\n", line.trim()).as_bytes());
    }
    let _ = std::io::copy(&mut &f, &mut std::io::sink()); // wait for the client to close so the verdict is not lost
}

pub fn server(name: &str, count: usize, timeout_s: u64, expect: &str) -> bool {
    let me = match own_sid() {
        Ok(s) => s,
        Err(e) => {
            J::new().s("event", "error").s("error", &e).emit();
            return false;
        }
    };
    let want = if expect.is_empty() {
        me.clone()
    } else {
        expect.to_string()
    };
    // Protected DACL, one ACE: GENERIC_ALL for the current user SID. SYSTEM/Administrators/Everyone get nothing.
    let sddl = wide(&format!("D:P(A;;GA;;;{me})"));
    let mut sd: *mut c_void = null_mut();
    // SAFETY: sd is freed with LocalFree before returning.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            null_mut(),
        )
    } == 0
    {
        J::new().s("event", "error").s("error", "sddl").emit();
        return false;
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(timeout_s));
        J::new().s("event", "timeout").emit();
        std::process::exit(3);
    });
    let mut cur = match create_instance(name, true, &sa) {
        Ok(h) => h,
        Err(e) => {
            J::new()
                .s("event", "error")
                .s("error", "CreateNamedPipeW")
                .n("win32_error", e as i64)
                .emit();
            return false;
        }
    };
    J::new()
        .s("event", "listening")
        .s("dacl", "D:P(A;;GA;;;<current-user>)")
        .b("first_instance_exclusive", true)
        .b("reject_remote", true)
        .emit();
    let mut workers = Vec::new();
    for i in 0..count {
        // SAFETY: blocking connect; ERROR_PIPE_CONNECTED (535) means the client raced us and is fine.
        let ok = unsafe { ConnectNamedPipe(cur, null_mut()) != 0 || GetLastError() == 535 };
        if !ok {
            break;
        }
        let conn = cur as usize;
        let want = want.clone();
        workers.push(std::thread::spawn(move || serve(conn, &want)));
        if i + 1 < count {
            // The next instance is created while the name is still held by the connected one.
            match create_instance(name, false, &sa) {
                Ok(h) => cur = h,
                Err(_) => break,
            }
        }
    }
    for w in workers {
        let _ = w.join();
    }
    // SAFETY: allocated by ConvertStringSecurityDescriptor...
    unsafe { LocalFree(sd) };
    true
}

/// std-only client: OpenOptions::security_qos_flags sets SECURITY_SQOS_PRESENT | level. No unsafe, no FFI.
pub fn client(name: &str, level: &str) -> bool {
    let q = match level {
        "anonymous" => SECURITY_ANONYMOUS,
        "impersonation" => SECURITY_IMPERSONATION,
        _ => SECURITY_IDENTIFICATION,
    };
    let path = format!(r"\\.\pipe\{name}");
    let mut j = J::new();
    j.s("op", "pipe-client").s("level", level);
    let deadline = Instant::now() + Duration::from_secs(5);
    let f = loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(q)
            .open(&path)
        {
            Ok(f) => break f,
            // ERROR_FILE_NOT_FOUND (2) / ERROR_PIPE_BUSY (231): server not up yet or all instances busy
            Err(e)
                if matches!(e.raw_os_error(), Some(2) | Some(231)) && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => {
                j.b("ok", false).s("error", &e.to_string()).emit();
                return false;
            }
        }
    };
    let mut r = BufReader::new(&f);
    let mut verdict = String::new();
    let _ = r.read_line(&mut verdict);
    let verdict = verdict.trim().to_string();
    j.s("verdict", &verdict);
    if verdict != "ok" {
        j.b("ok", false).emit();
        return false;
    }
    let _ = (&f).write_all(b"hello\n");
    let mut echo = String::new();
    let _ = r.read_line(&mut echo);
    let echo = echo.trim().to_string();
    let ok = echo == "echo:hello";
    j.s("echo", &echo).b("ok", ok).emit();
    ok
}
