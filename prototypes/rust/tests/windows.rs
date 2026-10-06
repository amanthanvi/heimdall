//! Native Windows black-box tests (round 4, contract §9.6). Built on the Mac with
//! `cargo zigbuild --tests --target x86_64-pc-windows-gnu` and run on a Windows host
//! with `HEIMDALL_PROTO_BIN` (the heimdall-proto.exe under test) and
//! `HEIMDALL_G02_FIXTURES` set. Named pipes are created in-process with a protected
//! DACL that grants only the current user, reject remote clients, and are named
//! `hm-M00-T05-x1b-fix-rust-<pid>-<n>`. Nothing touches a real agent or ~/.ssh.
#![cfg(windows)]
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::Value;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const CANARY_PREFIX: &str = concat!("HEIMDALL_", "CANARY_");

fn bin() -> String {
    std::env::var("HEIMDALL_PROTO_BIN")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_heimdall-proto").to_string())
}

fn fixtures() -> PathBuf {
    let p = std::env::var_os("HEIMDALL_G02_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/g02/profiles")
        });
    assert!(
        p.join("homelab.toml").is_file(),
        "G02 fixtures not found; set HEIMDALL_G02_FIXTURES"
    );
    p
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// String SID of the current process user.
fn my_sid() -> String {
    unsafe {
        let mut tok: HANDLE = std::ptr::null_mut();
        assert_ne!(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok),
            0
        );
        let mut len = 0u32;
        GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        assert_ne!(
            GetTokenInformation(tok, TokenUser, buf.as_mut_ptr().cast(), len, &mut len),
            0
        );
        CloseHandle(tok);
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s: *mut u16 = std::ptr::null_mut();
        assert_ne!(ConvertSidToStringSidW(tu.User.Sid, &mut s), 0);
        let mut n = 0;
        while *s.add(n) != 0 {
            n += 1;
        }
        let out = std::ffi::OsString::from_wide(std::slice::from_raw_parts(s, n))
            .into_string()
            .unwrap();
        LocalFree(s.cast());
        out
    }
}

static SEQ: AtomicU32 = AtomicU32::new(0);

/// A fresh pipe name carrying the task id.
fn pipe_name() -> String {
    format!(
        r"\\.\pipe\hm-M00-T05-x1b-fix-rust-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    )
}

/// One listening pipe instance (first instance, current-user-only DACL, local clients
/// only). A client can connect to it at once; nothing is read or written unless the
/// caller does so.
fn create_pipe(name: &str) -> OwnedHandle {
    let sddl = wide(OsStr::new(&format!("D:P(A;;GA;;;{})", my_sid())));
    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        assert_ne!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut()
            ),
            0
        );
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let wname = wide(OsStr::new(name));
        let h = CreateNamedPipeW(
            wname.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            &sa,
        );
        LocalFree(sd);
        assert_ne!(h, INVALID_HANDLE_VALUE, "CreateNamedPipeW failed");
        OwnedHandle::from_raw_handle(h)
    }
}

/// Run heimdall-proto with a hard deadline; a run still alive at the deadline is
/// killed through its own handle and reported as `None`.
fn run_bounded(args: &[&OsStr], limit: Duration) -> (Option<Output>, Duration) {
    let mut c = Command::new(bin())
        .args(args)
        .env("SSH_AUTH_SOCK", r"\\.\pipe\hm-M00-T05-x1b-fix-rust-none")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let t = Instant::now();
    while c.try_wait().unwrap().is_none() && t.elapsed() < limit {
        std::thread::sleep(Duration::from_millis(5));
    }
    let el = t.elapsed();
    if c.try_wait().unwrap().is_none() {
        let _ = c.kill();
        let _ = c.wait();
        return (None, el);
    }
    (Some(c.wait_with_output().unwrap()), el)
}

fn one_json(o: &Output) -> Value {
    let s = std::str::from_utf8(&o.stdout).expect("stdout utf-8");
    assert!(s.ends_with('\n') && s.matches('\n').count() == 1, "{s:?}");
    for stream in [&o.stdout, &o.stderr] {
        assert!(!String::from_utf8_lossy(stream).contains(CANARY_PREFIX));
    }
    serde_json::from_str(s).unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "hm-x1b-rust-{tag}-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn profile_show(path: &Path) -> (Option<Output>, Duration) {
    run_bounded(
        &[
            OsStr::new("profile"),
            OsStr::new("show"),
            OsStr::new("--json"),
            OsStr::new("--file"),
            path.as_os_str(),
        ],
        Duration::from_secs(5),
    )
}

/// §9.6 K14: a named pipe whose server never writes, given as --file, is USAGE_ERROR
/// (exit 2) within 2 s. NUL and a directory are the same class.
#[test]
fn k14_named_pipe_nul_and_dir_as_profile_file() {
    let name = pipe_name();
    let _srv = create_pipe(&name);
    let d = scratch("k14");
    let dir = d.join("a dir é");
    std::fs::create_dir(&dir).unwrap();
    for p in [Path::new(&name), Path::new("NUL"), dir.as_path()] {
        let (o, el) = profile_show(p);
        let o = o.unwrap_or_else(|| panic!("{}: still running after {el:?}", p.display()));
        assert!(el < Duration::from_secs(2), "{}: {el:?}", p.display());
        assert_eq!(o.status.code(), Some(2), "{}", p.display());
        let v = one_json(&o);
        assert_eq!(v["code"], "USAGE_ERROR", "{}", p.display());
        assert_eq!(v["state"], "failed");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// The shared loader used by both `profile show` and `tui` (§5 reuses §2): a pipe is
/// refused without blocking. Run on a worker thread so a regression fails instead of
/// hanging the test binary.
#[test]
fn k14_shared_loader_refuses_pipe_without_blocking() {
    let name = pipe_name();
    let _srv = create_pipe(&name);
    let (tx, rx) = std::sync::mpsc::channel();
    let p = PathBuf::from(&name);
    std::thread::spawn(move || {
        let _ = tx.send(heimdall_proto::profile::load_file(&p).map(|_| ()));
    });
    let r = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("load_file blocked on a named pipe for 2 s");
    let e = r.expect_err("a pipe must not load as a profile");
    assert_eq!(e.code.as_str(), "USAGE_ERROR");
}

/// Regular files still load (the GetFileType check does not reject disk files),
/// including under a path with a space and non-ASCII characters.
#[test]
fn regular_profile_files_still_load() {
    let f = fixtures();
    for p in [
        f.join("homelab.toml"),
        f.join("spaced dir ü").join("prøfile homelab.toml"),
    ] {
        let (o, _) = profile_show(&p);
        let o = o.expect("profile show timed out");
        assert_eq!(o.status.code(), Some(0), "{}", p.display());
        assert_eq!(one_json(&o)["code"], "PROFILE_OK");
    }
}

fn agent_list(sock: &Path) -> (Option<Output>, Duration) {
    run_bounded(
        &[
            OsStr::new("agent"),
            OsStr::new("list"),
            OsStr::new("--socket"),
            sock.as_os_str(),
            OsStr::new("--timeout-ms"),
            OsStr::new("2000"),
            OsStr::new("--json"),
        ],
        Duration::from_secs(5),
    )
}

/// §9.6: a regular file (and NUL, and a directory) given as --socket is refused
/// without modification: exit 5 AGENT_UNAVAILABLE (or exit 2), content and mtime
/// unchanged.
#[test]
fn socket_non_pipe_paths_refused_without_modification() {
    let d = scratch("sock");
    let file = d.join("not a socket ü.bin");
    let before: Vec<u8> = (0..4096u32).map(|i| (i * 7 + 3) as u8).collect();
    std::fs::write(&file, &before).unwrap();
    let mtime0 = std::fs::metadata(&file).unwrap().modified().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let dir = d.join("a dir");
    std::fs::create_dir(&dir).unwrap();
    for p in [file.as_path(), Path::new("NUL"), dir.as_path()] {
        let (o, el) = agent_list(p);
        let o = o.unwrap_or_else(|| panic!("{}: still running after {el:?}", p.display()));
        let v = one_json(&o);
        let ok = (o.status.code() == Some(5) && v["code"] == "AGENT_UNAVAILABLE")
            || (o.status.code() == Some(2) && v["code"] == "USAGE_ERROR");
        assert!(
            ok,
            "{}: exit {:?} code {}",
            p.display(),
            o.status.code(),
            v["code"]
        );
    }
    assert_eq!(
        std::fs::read(&file).unwrap(),
        before,
        "file content changed"
    );
    assert_eq!(
        std::fs::metadata(&file).unwrap().modified().unwrap(),
        mtime0,
        "file mtime changed"
    );
    let _ = std::fs::remove_dir_all(&d);
}

fn sstr(b: &[u8]) -> Vec<u8> {
    let mut v = (b.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(b);
    v
}

/// A real pipe endpoint still works: the request is exactly the type-11 frame and the
/// identity is reported (regression guard for the GetFileType check).
#[test]
fn agent_pipe_endpoint_still_answers() {
    let name = pipe_name();
    let srv = create_pipe(&name);
    let mut blob = sstr(b"ssh-ed25519");
    blob.extend_from_slice(&sstr(&[7u8; 32]));
    let mut body = vec![12u8];
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&sstr(&blob));
    body.extend_from_slice(&sstr(b"x1b fixture"));
    let mut reply = (body.len() as u32).to_be_bytes().to_vec();
    reply.extend_from_slice(&body);
    let h = std::thread::spawn(move || {
        use std::os::windows::io::AsRawHandle;
        // Returns 0 with ERROR_PIPE_CONNECTED when the client was faster; both are fine.
        unsafe { ConnectNamedPipe(srv.as_raw_handle(), std::ptr::null_mut()) };
        let mut f = File::from(srv);
        let mut req = [0u8; 5];
        f.read_exact(&mut req).unwrap();
        f.write_all(&reply).unwrap();
        let mut rest = Vec::new();
        let _ = f.read_to_end(&mut rest); // ends when the client closes
        (req, rest)
    });
    let (o, _) = agent_list(Path::new(&name));
    let o = o.expect("agent list timed out");
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    let v = one_json(&o);
    assert_eq!(v["code"], "AGENT_OK");
    assert_eq!(v["data"]["identities"][0]["key_type"], "ssh-ed25519");
    let (req, rest) = h.join().unwrap();
    assert_eq!(req, [0, 0, 0, 1, 11]);
    assert!(rest.is_empty(), "client sent more than one request");
}
