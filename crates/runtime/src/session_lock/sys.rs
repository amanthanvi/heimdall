//! The session-lock FFI boundary (ADR-0008 D9 item 3; m03-plan U9;
//! `docs/architecture/overview.md` §9 item 6). The only `unsafe` of the session-lock
//! sources: each block is one FFI call (or one read of an FFI-returned value) wrapped
//! in a safe function, with its invariant stated at the call. No `unsafe` leaves this
//! module, and no raw pointer or handle leaves it except as an opaque owner type that
//! frees it exactly once on drop. Linux uses `zbus` and needs nothing here.
//!
//! macOS registers **no** `CFNotificationCenter` observer: the distributed center
//! delivers its callbacks only on the process's main-thread run loop (observed, see
//! `macos.rs`), which the runtime's main thread (tokio's) never runs, so the source
//! polls the session dictionary on its own thread instead (questions file U9-Q4).
//!
//! | Platform | `unsafe` call | Invariant |
//! |---|---|---|
//! | macOS | `CGSessionCopyCurrentDictionary()` (CoreGraphics, declared here: no pinned crate has it) | no arguments; called only on the source's own polling thread; the returned dictionary (Copy rule) is checked non-null and released with `CFRelease` exactly once, after its last read; `NULL` (no GUI session) reads `unavailable` at start and `unknown` later |
//! | macOS | `CFDictionaryGetValue(dict, key)`, `CFGetTypeID`, `CFBooleanGetTypeID`, `CFBooleanGetValue` | `dict` is the live dictionary above; `key` a live `CFString`; the value (Get rule, not retained) is read before the dictionary is released; a value that is not a `CFBoolean` is never read as one: a non-boolean `CGSSessionScreenIsLocked` reads `locked`, a non-boolean `kCGSessionOnConsoleKey` reads "not on console" (fail closed) |
//! | Windows | `GetModuleHandleW(NULL)` | this executable's module; no reference count is taken, nothing to free |
//! | Windows | `RegisterClassW(&WNDCLASSW)` | a fully initialized class whose name buffer outlives the call; `ERROR_CLASS_ALREADY_EXISTS` (a second source in one process) is accepted; the class is never unregistered while a window may use it |
//! | Windows | `CreateWindowExW(…, HWND_MESSAGE, …)` / `DestroyWindow` | a hidden message-only window, created and destroyed exactly once on the source's own thread (`MessageWindow`), never shared with another thread |
//! | Windows | `WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)` / `WTSUnRegisterSessionNotification` | registered once after the window exists and unregistered once before it is destroyed; a failed registration destroys the window and reads `unavailable` |
//! | Windows | `SetTimer(hwnd, 1, tick, NULL)` / `KillTimer` | the backstop tick (posted `WM_TIMER`), set and killed once with the window |
//! | Windows | `GetMessageW(&msg, NULL, 0, 0)` / `DispatchMessageW(&msg)` | a valid out-pointer on the source thread; `-1` ends the loop; `0` (`WM_QUIT`) ends it |
//! | Windows | the window procedure (`WM_WTSSESSION_CHANGE`, `WM_TIMER`, else `DefWindowProcW`) | called by the system on the source thread only; records into the latch through a thread-local, never unwinds, never calls into the store |
//! | Windows | `GetCurrentThreadId` / `PostThreadMessageW(thread, WM_QUIT, 0, 0)` | integers only; a failed post is retried, and the tick bounds the shutdown anyway |
//! | Windows | `WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSSessionInfoEx, &buf, &bytes)` / `WTSFreeMemory(buf)` | valid out-pointers; the buffer is read only when non-null and at least `size_of::<WTSINFOEXW>()` bytes, unaligned, its union member only for `Level == 1`; freed with `WTSFreeMemory` exactly once; a failed query or an unknown flag reads `unknown` |

#![allow(unsafe_code)]

#[cfg(target_os = "macos")]
pub(super) use mac::{CgSession, cg_session};
#[cfg(windows)]
pub(super) use win::{MessageWindow, current_thread_id, post_quit, pump, session_locked};

#[cfg(target_os = "macos")]
mod mac {
    use core_foundation::base::TCFType;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{CFGetTypeID, CFRelease};
    use core_foundation_sys::dictionary::{CFDictionaryGetValue, CFDictionaryRef};
    use core_foundation_sys::number::{CFBooleanGetTypeID, CFBooleanGetValue, CFBooleanRef};

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    /// The console session as CoreGraphics reports it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum CgSession {
        /// No GUI session for this process (`NULL`).
        None,
        /// A session.
        Present {
            /// `CGSSessionScreenIsLocked` (absent: unlocked).
            locked: bool,
            /// `kCGSessionOnConsoleKey` (absent: on console).
            on_console: bool,
        },
    }

    enum Entry {
        Absent,
        Bool(bool),
        Other,
    }

    fn entry(dict: CFDictionaryRef, key: &str) -> Entry {
        let k = CFString::new(key);
        // SAFETY: `dict` is the live dictionary the caller holds (released only after
        // this returns); `k` lives to the end of this function. Get rule: the value is
        // not retained and is read only here, before the dictionary is released.
        let v = unsafe { CFDictionaryGetValue(dict, k.as_concrete_TypeRef().cast()) };
        if v.is_null() {
            return Entry::Absent;
        }
        // SAFETY: `v` is a non-null CF object owned by `dict`; both are type queries.
        let is_bool = unsafe { CFGetTypeID(v) == CFBooleanGetTypeID() };
        if !is_bool {
            return Entry::Other;
        }
        let b: CFBooleanRef = v.cast();
        // SAFETY: `b` is a `CFBoolean` (type checked above), owned by `dict`.
        Entry::Bool(unsafe { CFBooleanGetValue(b) })
    }

    /// Read the session dictionary once (module table).
    pub(crate) fn cg_session() -> CgSession {
        // SAFETY: no arguments; returns an owned dictionary (Copy rule) or NULL.
        let dict = unsafe { CGSessionCopyCurrentDictionary() };
        if dict.is_null() {
            return CgSession::None;
        }
        let locked = match entry(dict, "CGSSessionScreenIsLocked") {
            Entry::Absent => false,
            Entry::Bool(b) => b,
            Entry::Other => true,
        };
        let on_console = match entry(dict, "kCGSessionOnConsoleKey") {
            Entry::Absent => true,
            Entry::Bool(b) => b,
            Entry::Other => false,
        };
        // SAFETY: `dict` is the non-null owned reference above; this is its one release,
        // after its last read.
        unsafe { CFRelease(dict.cast()) };
        CgSession::Present { locked, on_console }
    }
}

#[cfg(windows)]
mod win {
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};

    use windows_sys::Win32::Foundation::{
        ERROR_CLASS_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, WPARAM,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::System::RemoteDesktop::{
        NOTIFY_FOR_THIS_SESSION, WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
        WTS_SESSIONSTATE_LOCK, WTS_SESSIONSTATE_UNLOCK, WTSFreeMemory, WTSINFOEXW,
        WTSQuerySessionInformationW, WTSRegisterSessionNotification, WTSSessionInfoEx,
        WTSUnRegisterSessionNotification,
    };
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        HWND_MESSAGE, KillTimer, MSG, PostThreadMessageW, RegisterClassW, SetTimer, WM_QUIT,
        WM_TIMER, WM_WTSSESSION_CHANGE, WNDCLASSW,
    };

    const TIMER_ID: usize = 1;

    fn class_name() -> Vec<u16> {
        "HeimdallSessionLockWindow"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    fn last_error() -> u32 {
        // SAFETY: reads this thread's last-error value; no arguments.
        unsafe { GetLastError() }
    }

    /// The hidden message-only window of the source thread (module table).
    pub(crate) struct MessageWindow {
        hwnd: HWND,
        timer: bool,
    }

    impl MessageWindow {
        /// Create the window, register for this session's notifications and set the
        /// backstop tick (`tick_ms`). `Err` carries the Win32 error code.
        pub(crate) fn create(tick_ms: u32) -> Result<Self, u32> {
            let class = class_name();
            // SAFETY: NULL names this process's executable module; no reference count.
            let hinstance = unsafe { GetModuleHandleW(ptr::null()) };
            if hinstance.is_null() {
                return Err(last_error());
            }
            let wc = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(wndproc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinstance,
                hIcon: ptr::null_mut(),
                hCursor: ptr::null_mut(),
                hbrBackground: ptr::null_mut(),
                lpszMenuName: ptr::null(),
                lpszClassName: class.as_ptr(),
            };
            // SAFETY: `wc` is fully initialized and `class` outlives the call (the
            // system copies the name).
            if unsafe { RegisterClassW(&raw const wc) } == 0 {
                let e = last_error();
                if e != ERROR_CLASS_ALREADY_EXISTS {
                    return Err(e);
                }
            }
            // SAFETY: a message-only window (`HWND_MESSAGE` parent) of the class above;
            // NULL title, menu and creation parameter are allowed.
            let hwnd = unsafe {
                CreateWindowExW(
                    0,
                    class.as_ptr(),
                    ptr::null(),
                    0,
                    0,
                    0,
                    0,
                    0,
                    HWND_MESSAGE,
                    ptr::null_mut(),
                    hinstance,
                    ptr::null(),
                )
            };
            if hwnd.is_null() {
                return Err(last_error());
            }
            // SAFETY: `hwnd` is the live window above, owned by this thread.
            if unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } == 0 {
                let e = last_error();
                // SAFETY: destroys the window created above, on its thread, once.
                unsafe { DestroyWindow(hwnd) };
                return Err(e);
            }
            // SAFETY: the live window; timer 1; no TIMERPROC, so `WM_TIMER` is posted to
            // this thread's queue.
            let timer = unsafe { SetTimer(hwnd, TIMER_ID, tick_ms, None) } != 0;
            Ok(Self { hwnd, timer })
        }
    }

    impl Drop for MessageWindow {
        fn drop(&mut self) {
            // SAFETY: the live window this value owns, on its own thread: the timer is
            // killed, the registration removed and the window destroyed, each once.
            unsafe {
                if self.timer {
                    KillTimer(self.hwnd, TIMER_ID);
                }
                WTSUnRegisterSessionNotification(self.hwnd);
                DestroyWindow(self.hwnd);
            }
        }
    }

    unsafe extern "system" fn wndproc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_WTSSESSION_CHANGE => {
                super::super::windows::on_session_change(u32::try_from(wparam).unwrap_or(u32::MAX));
                0
            }
            WM_TIMER => {
                super::super::windows::on_tick();
                0
            }
            // SAFETY: the parameters the system passed for this window.
            _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
        }
    }

    /// Pump this thread's messages until `WM_QUIT`, `stop`, or an error (`false`).
    pub(crate) fn pump(stop: &AtomicBool) -> bool {
        let mut msg = MSG::default();
        loop {
            if stop.load(Ordering::SeqCst) {
                return true;
            }
            // SAFETY: a valid out-pointer; NULL retrieves every message of this thread.
            let r = unsafe { GetMessageW(&raw mut msg, ptr::null_mut(), 0, 0) };
            if r == 0 {
                return true;
            }
            if r == -1 {
                return false;
            }
            // SAFETY: the message GetMessageW just retrieved on this thread.
            unsafe { DispatchMessageW(&raw const msg) };
        }
    }

    /// This thread's ID.
    pub(crate) fn current_thread_id() -> u32 {
        // SAFETY: no arguments.
        unsafe { GetCurrentThreadId() }
    }

    /// Post `WM_QUIT` to `thread` (`false` when the post failed).
    pub(crate) fn post_quit(thread: u32) -> bool {
        // SAFETY: integers only.
        unsafe { PostThreadMessageW(thread, WM_QUIT, 0, 0) != 0 }
    }

    /// The current session's lock flag: `Some(true)` locked, `Some(false)` unlocked,
    /// `None` unknown (module table).
    pub(crate) fn session_locked() -> Option<bool> {
        let mut buf: windows_sys::core::PWSTR = ptr::null_mut();
        let mut bytes: u32 = 0;
        // SAFETY: valid out-pointers; the local server and the current session.
        let ok = unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                WTS_CURRENT_SESSION,
                WTSSessionInfoEx,
                &raw mut buf,
                &raw mut bytes,
            )
        };
        if ok == 0 || buf.is_null() {
            return None;
        }
        let enough = usize::try_from(bytes).is_ok_and(|b| b >= size_of::<WTSINFOEXW>());
        let out = if enough {
            // SAFETY: `buf` is a WTS allocation of at least `size_of::<WTSINFOEXW>()`
            // bytes holding a `WTSINFOEXW`; read unaligned into a local copy.
            let info: WTSINFOEXW = unsafe { ptr::read_unaligned(buf.cast::<WTSINFOEXW>()) };
            if info.Level == 1 {
                // SAFETY: `Level == 1` selects the `WTSInfoExLevel1` member.
                let flags = unsafe { info.Data.WTSInfoExLevel1.SessionFlags }.cast_unsigned();
                match flags {
                    WTS_SESSIONSTATE_LOCK => Some(true),
                    WTS_SESSIONSTATE_UNLOCK => Some(false),
                    _ => None,
                }
            } else {
                None
            }
        } else {
            None
        };
        // SAFETY: frees the buffer WTSQuerySessionInformationW returned, exactly once.
        unsafe { WTSFreeMemory(buf.cast()) };
        out
    }
}
