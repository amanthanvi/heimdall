//! ⟨M04 U2⟩ The environment OpenSSH for Windows needs to start (found by the M03 exit
//! suite's Windows diagnosis).
//!
//! **The failure.** The in-box `ssh.exe` (OpenSSH for Windows 9.5p2) launched with a stripped
//! environment exits 255 with no output and without connecting; `ssh -G` fails the same way.
//! It resolves its system-wide files through `__PROGRAMDATA__` (`%ProgramData%\ssh`) and the
//! system directories through the standard variables. A Heimdall process that runs with a
//! stripped environment would otherwise lose every `ssh.exe` it starts: the owned
//! connections, the effective-configuration check, enrollment verification (silently, as
//! `inconclusive`) and the local queries.
//!
//! **The fix.** Every product launch of an OpenSSH client calls [`fill_openssh_environment`]
//! on its command. On Windows, each of [`OPENSSH_WINDOWS_VARS`] that the child would lack
//! (absent from what it inherits, or removed or never set when its environment is cleared)
//! is set **from the operating system**, never from another variable:
//!
//! | Variable | Source |
//! |---|---|
//! | `ProgramData`, `ALLUSERSPROFILE` | `SHGetKnownFolderPath(FOLDERID_ProgramData)`; when this process has no `SystemDrive`, failing that, `<the drive of FOLDERID_Windows>\ProgramData` |
//! | `windir` | `SHGetKnownFolderPath(FOLDERID_Windows)` |
//! | `SystemDrive` | the drive of `FOLDERID_Windows` (`C:`) |
//!
//! **Without this process's `SystemDrive`** ⟨M06 exit, PC job 53⟩. Sources: Microsoft Learn,
//! *KNOWNFOLDERID* (<https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid>) and
//! *SHGetKnownFolderPath function*
//! (<https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath>). `FOLDERID_ProgramData`
//! is a FIXED folder whose documented default path is `%ALLUSERSPROFILE%` (`%ProgramData%`,
//! `%SystemDrive%\ProgramData`) (Microsoft Learn, *KNOWNFOLDERID*); the shell expands it from
//! the **calling** process's environment, so a Heimdall started with a cleared environment (no
//! `SystemDrive`) gets `0x80070003` from `SHGetKnownFolderPath` (observed natively). The call
//! takes no environment of its own: `hToken` only selects a user (null: the current user;
//! *SHGetKnownFolderPath*), and setting `SystemDrive` in this process would change every other
//! thread's environment, so neither is used. Instead, only in that case and only when the
//! known folder fails, `ProgramData` is the documented default `%SystemDrive%\ProgramData`
//! with the system drive derived from the Windows directory (`FOLDERID_Windows`, which resolves
//! without `SystemDrive`; observed), which is also the `SystemDrive` the child gets. A known
//! folder that does resolve (a relocated `ProgramData`) always wins, and when this process has
//! `SystemDrive` and the call still fails, nothing is derived. This process's own environment
//! is never changed.
//!
//! Nothing else is ever added, and a variable the child already has is never changed. A
//! value the operating system cannot give is left unset (the launch then fails as it did
//! before, and the caller's own error path reports it). Elsewhere it does nothing.
//!
//! The `unsafe` (Windows: `SHGetKnownFolderPath`, `CoTaskMemFree`) is in the inventory table of
//! `sys/mod.rs` and the overview's §9.

use std::ffi::{OsStr, OsString};
use std::process::Command;

/// The variables OpenSSH for Windows needs that a stripped environment can lack, and the only
/// ones [`fill_openssh_environment`] ever sets.
pub const OPENSSH_WINDOWS_VARS: [&str; 4] =
    ["ProgramData", "ALLUSERSPROFILE", "SystemDrive", "windir"];

/// Whether `program` names an OpenSSH client (`ssh`, `ssh.exe`, any case): the launches
/// [`fill_openssh_environment`] is for.
#[must_use]
pub fn is_ssh_program(program: &OsStr) -> bool {
    let text = program.to_string_lossy();
    let name = text.rsplit(['/', '\\']).next().unwrap_or("");
    let stem = name
        .len()
        .checked_sub(4)
        .filter(|&i| {
            name.get(i..)
                .is_some_and(|e| e.eq_ignore_ascii_case(".exe"))
        })
        .and_then(|i| name.get(..i))
        .unwrap_or(name);
    stem.eq_ignore_ascii_case("ssh")
}

/// Which of [`OPENSSH_WINDOWS_VARS`] the child of `cmd` would lack. `inherits`: the child
/// starts from this process's environment (`parent` reads it), so a variable present there
/// and not removed on `cmd` counts; otherwise (a cleared environment) only a variable set on
/// `cmd` counts. Names compare ASCII case-insensitively, as Windows does. Pure but for
/// `parent`.
#[must_use]
pub fn missing_openssh_vars(
    cmd: &Command,
    inherits: bool,
    parent: &dyn Fn(&str) -> Option<OsString>,
) -> Vec<&'static str> {
    OPENSSH_WINDOWS_VARS
        .into_iter()
        .filter(|name| {
            // The last change on `cmd` wins: set, or removed.
            let change = cmd
                .get_envs()
                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                .last()
                .map(|(_, v)| v.is_some_and(|v| !v.is_empty()));
            let present = match change {
                Some(set) => set,
                None => inherits && parent(name).is_some_and(|v| !v.is_empty()),
            };
            !present
        })
        .collect()
}

/// The drive (`C:`) of a Windows directory path (`C:\\Windows`, `C:`), or `None` when it does
/// not start with a drive letter and a colon followed by a separator or nothing (a UNC or
/// relative path). Pure; any platform.
#[must_use]
pub fn drive_of_windows_dir(windows_dir: &str) -> Option<String> {
    let mut chars = windows_dir.chars();
    let letter = chars.next().filter(char::is_ascii_alphabetic)?;
    chars.next().filter(|&c| c == ':')?;
    match chars.next() {
        None | Some('\\' | '/') => Some(format!("{letter}:")),
        Some(_) => None,
    }
}

/// The documented default `ProgramData` on `drive` (`%SystemDrive%\\ProgramData`; Microsoft
/// Learn, *KNOWNFOLDERID*, `FOLDERID_ProgramData`). Pure; any platform.
#[must_use]
pub fn default_program_data(drive: &str) -> String {
    format!("{drive}\\ProgramData")
}

/// Whether a known folder's value is a usable absolute drive path: it has a drive
/// ([`drive_of_windows_dir`]) and nothing left unexpanded (`%`). Pure; any platform.
#[must_use]
pub fn is_usable_folder(path: &str) -> bool {
    drive_of_windows_dir(path).is_some() && path.len() > 2 && !path.contains('%')
}

/// Set on `cmd` each of [`OPENSSH_WINDOWS_VARS`] its child would lack (module docs), from the
/// operating system. `inherits`: whether the child starts from this process's environment
/// (`false` when the caller cleared it). Windows only; a no-op elsewhere.
pub fn fill_openssh_environment(cmd: &mut Command, inherits: bool) {
    #[cfg(windows)]
    {
        let missing = missing_openssh_vars(cmd, inherits, &|n| std::env::var_os(n));
        let has_system_drive = std::env::var_os("SystemDrive").is_some_and(|v| !v.is_empty());
        for name in missing {
            if let Some(value) = os::value_of(name, has_system_drive) {
                cmd.env(name, value);
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (cmd, inherits);
    }
}

#[cfg(windows)]
mod os {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt as _;

    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramData, FOLDERID_Windows, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };
    use windows_sys::core::{GUID, PWSTR};

    /// A known folder's path (`None` when the call fails).
    pub(super) fn known_folder(id: &GUID) -> Option<OsString> {
        let mut path: PWSTR = std::ptr::null_mut();
        // SAFETY: `id` is a valid known-folder GUID that outlives the call; no token (the
        // current user); `path` is a valid out-pointer. On success the buffer is a
        // NUL-terminated wide string the shell allocated, freed below exactly once with
        // `CoTaskMemFree` as the API requires; on failure it is null or must still be freed.
        let hr = unsafe {
            SHGetKnownFolderPath(
                id,
                KF_FLAG_DEFAULT as u32,
                std::ptr::null_mut(),
                &raw mut path,
            )
        };
        let value = if hr >= 0 && !path.is_null() {
            // SAFETY: `path` is a NUL-terminated wide string (above); the scan stops at the
            // NUL and is bounded.
            let len = (0..32_768usize)
                .find(|&i| unsafe { *path.add(i) } == 0)
                .unwrap_or(0);
            // SAFETY: `len` units are readable (found above, before the NUL).
            let units = unsafe { std::slice::from_raw_parts(path, len) };
            (len > 0).then(|| OsString::from_wide(units))
        } else {
            None
        };
        // SAFETY: `path` came from `SHGetKnownFolderPath` (or is null, which is allowed).
        unsafe { CoTaskMemFree(path.cast()) };
        value
    }

    /// The system drive (`C:`), from the Windows directory (`FOLDERID_Windows`).
    pub(super) fn system_drive() -> Option<String> {
        let windows = known_folder(&FOLDERID_Windows)?;
        super::drive_of_windows_dir(windows.to_str()?)
    }

    /// The `ProgramData` folder: the known folder when it resolves; otherwise, only when this
    /// process has no `SystemDrive` (`has_system_drive`; the known folder cannot expand then),
    /// the documented default on the system drive (module docs).
    pub(super) fn program_data(has_system_drive: bool) -> Option<OsString> {
        known_folder(&FOLDERID_ProgramData)
            .filter(|v| v.to_str().is_some_and(super::is_usable_folder))
            .or_else(|| {
                // The derivation (PC job 53): without it, a cleared environment gets nothing.
                (!has_system_drive)
                    .then(system_drive)
                    .flatten()
                    .map(|d| OsString::from(super::default_program_data(&d)))
            })
    }

    /// The value of one of `OPENSSH_WINDOWS_VARS`, from the operating system.
    /// `has_system_drive`: whether this process's environment has `SystemDrive`.
    pub(super) fn value_of(name: &str, has_system_drive: bool) -> Option<OsString> {
        match name {
            "ProgramData" | "ALLUSERSPROFILE" => program_data(has_system_drive),
            "windir" => known_folder(&FOLDERID_Windows),
            "SystemDrive" => system_drive().map(OsString::from),
            _ => None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// What counts as present: inherited and not removed, or set on the command; a cleared
    /// environment counts only what the command sets; names compare case-insensitively;
    /// an empty value is absent. Nothing outside the four names is ever reported.
    #[test]
    fn missing_openssh_vars_reads_inherited_set_removed_and_cleared() {
        let parent =
            |n: &str| (n == "ProgramData" || n == "windir").then(|| OsString::from("C:\\x"));
        let cmd = Command::new("ssh");
        assert_eq!(
            missing_openssh_vars(&cmd, true, &parent),
            ["ALLUSERSPROFILE", "SystemDrive"]
        );
        assert_eq!(
            missing_openssh_vars(&cmd, false, &parent),
            OPENSSH_WINDOWS_VARS
        );
        let mut cmd = Command::new("ssh");
        cmd.env("PROGRAMDATA", "C:\\p")
            .env("SystemDrive", "")
            .env_remove("WINDIR")
            .env("ALLUSERSPROFILE", "C:\\p");
        assert_eq!(
            missing_openssh_vars(&cmd, true, &parent),
            ["SystemDrive", "windir"]
        );
        assert!(is_ssh_program(OsStr::new(
            "C:\\Windows\\System32\\OpenSSH\\ssh.exe"
        )));
        assert!(is_ssh_program(OsStr::new("/usr/bin/ssh")));
        assert!(!is_ssh_program(OsStr::new("ssh-keygen.exe")));
        assert!(!is_ssh_program(OsStr::new("git")));
    }

    /// ⟨M06 exit, PC job 53⟩ The pure part of the derivation: the drive of a Windows directory
    /// (`GetSystemWindowsDirectoryW` documents `C:\\Windows`, or `C:` for a root install), the
    /// documented default `ProgramData` on it, and which known-folder values are usable.
    #[test]
    fn the_system_drive_and_default_program_data_derive_from_the_windows_directory() {
        assert_eq!(drive_of_windows_dir("C:\\WINDOWS").as_deref(), Some("C:"));
        assert_eq!(drive_of_windows_dir("d:\\Windows").as_deref(), Some("d:"));
        assert_eq!(drive_of_windows_dir("E:").as_deref(), Some("E:"));
        assert_eq!(drive_of_windows_dir("C:/Windows").as_deref(), Some("C:"));
        for bad in [
            "",
            "C",
            "1:\\x",
            "CC:\\x",
            "C:x",
            "\\\\srv\\share",
            "\\\\?\\C:\\Windows",
            "Windows",
        ] {
            assert_eq!(drive_of_windows_dir(bad), None, "{bad}");
        }
        assert_eq!(default_program_data("C:"), "C:\\ProgramData");
        assert!(is_usable_folder("C:\\ProgramData"));
        assert!(is_usable_folder("D:\\Data\\ProgramData"));
        assert!(!is_usable_folder("%SystemDrive%\\ProgramData"));
        assert!(!is_usable_folder("C:\\%x%"));
        assert!(!is_usable_folder("C:"));
        assert!(!is_usable_folder("ProgramData"));
    }

    /// ⟨M06 exit, PC job 53⟩ The PC's case: a process started with a cleared environment that
    /// keeps only what the journey's driver keeps (`heimdall_testkit::console`: `SystemRoot`,
    /// `windir`, `ComSpec`, `PATHEXT`; `windows_controller_m06.rs`: `PATH`, `USERPROFILE`,
    /// `LOCALAPPDATA`, `APPDATA`, `TEMP`, `TMP`, `USERNAME`), so no `SystemDrive` and no
    /// `ProgramData`, runs the fill for a cleared and for an inherited child environment;
    /// both `SystemDrive` and `ProgramData` (and `ALLUSERSPROFILE`) reach the prepared
    /// command with the values this (full-environment) process resolves, and the child
    /// process's own environment is unchanged. The child is this test binary re-run on this
    /// test alone, recognized by a marker variable.
    #[cfg(windows)]
    #[test]
    fn the_fill_supplies_system_drive_and_program_data_without_the_callers_system_drive() {
        const CHILD: &str = "HEIMDALL_TEST_OPENSSH_FILL_CHILD";
        const WANT_DRIVE: &str = "HEIMDALL_TEST_OPENSSH_FILL_DRIVE";
        const WANT_PD: &str = "HEIMDALL_TEST_OPENSSH_FILL_PROGRAMDATA";
        const MARKER: &str = "openssh-fill-child: ok";
        let lower = |v: &OsStr| v.to_string_lossy().to_ascii_lowercase();
        if std::env::var_os(CHILD).is_some() {
            for name in ["SystemDrive", "ProgramData", "ALLUSERSPROFILE"] {
                assert!(std::env::var_os(name).is_none(), "the child has {name}");
            }
            let want_drive = std::env::var_os(WANT_DRIVE).unwrap();
            let want_pd = std::env::var_os(WANT_PD).unwrap();
            for inherits in [false, true] {
                let mut cmd = Command::new("ssh");
                fill_openssh_environment(&mut cmd, inherits);
                let get = |name: &str| {
                    cmd.get_envs()
                        .find(|(k, _)| k.eq_ignore_ascii_case(name))
                        .and_then(|(_, v)| v)
                        .map(lower)
                };
                assert_eq!(
                    get("SystemDrive"),
                    Some(lower(&want_drive)),
                    "inherits={inherits}"
                );
                assert_eq!(
                    get("ProgramData"),
                    Some(lower(&want_pd)),
                    "inherits={inherits}"
                );
                assert_eq!(
                    get("ALLUSERSPROFILE"),
                    Some(lower(&want_pd)),
                    "inherits={inherits}"
                );
                if !inherits {
                    assert!(get("windir").is_some(), "windir");
                }
            }
            // The fix is local to the command: this process's environment is unchanged.
            assert!(std::env::var_os("SystemDrive").is_none());
            assert!(std::env::var_os("ProgramData").is_none());
            // The marker is the parent's evidence the child ran. ⟨PC job 55⟩ Under `--nocapture`
            // libtest has already printed `test <name> ... ` with no newline, so the marker starts
            // its own line.
            #[allow(clippy::print_stdout)]
            {
                println!("\n{MARKER}");
            }
            return;
        }
        // The parent: its own environment has SystemDrive, so its values are the reference.
        let want_drive = os::system_drive().unwrap();
        assert_eq!(
            std::env::var_os("SystemDrive").map(|v| lower(&v)),
            Some(want_drive.to_ascii_lowercase())
        );
        let want_pd =
            os::known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramData).unwrap();
        let module = module_path!();
        let name = format!(
            "{}::the_fill_supplies_system_drive_and_program_data_without_the_callers_system_drive",
            module.split_once("::").map_or(module, |(_, rest)| rest)
        );
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env_clear();
        for kept in [
            "SystemRoot",
            "windir",
            "ComSpec",
            "PATHEXT",
            "PATH",
            "USERPROFILE",
            "LOCALAPPDATA",
            "APPDATA",
            "TEMP",
            "TMP",
            "USERNAME",
        ] {
            if let Some(value) = std::env::var_os(kept) {
                child.env(kept, value);
            }
        }
        child
            .env(CHILD, "1")
            .env(WANT_DRIVE, &want_drive)
            .env(WANT_PD, &want_pd);
        let out = child.output().unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.lines().any(|l| l.trim_end().ends_with(MARKER)),
            "child exit {:?}\n{stdout}\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
