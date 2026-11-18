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
//! | `ProgramData`, `ALLUSERSPROFILE` | `SHGetKnownFolderPath(FOLDERID_ProgramData)` |
//! | `windir` | `SHGetKnownFolderPath(FOLDERID_Windows)` |
//! | `SystemDrive` | the drive of `FOLDERID_Windows` (`C:`) |
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

/// Set on `cmd` each of [`OPENSSH_WINDOWS_VARS`] its child would lack (module docs), from the
/// operating system. `inherits`: whether the child starts from this process's environment
/// (`false` when the caller cleared it). Windows only; a no-op elsewhere.
pub fn fill_openssh_environment(cmd: &mut Command, inherits: bool) {
    #[cfg(windows)]
    {
        let missing = missing_openssh_vars(cmd, inherits, &|n| std::env::var_os(n));
        for name in missing {
            if let Some(value) = os::value_of(name) {
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
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::path::{Component, Path};

    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_ProgramData, FOLDERID_Windows, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    };
    use windows_sys::core::{GUID, PWSTR};

    /// A known folder's path (`None` when the call fails).
    fn known_folder(id: &GUID) -> Option<OsString> {
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

    /// The value of one of `OPENSSH_WINDOWS_VARS`, from the operating system.
    pub(super) fn value_of(name: &str) -> Option<OsString> {
        match name {
            "ProgramData" | "ALLUSERSPROFILE" => known_folder(&FOLDERID_ProgramData),
            "windir" => known_folder(&FOLDERID_Windows),
            "SystemDrive" => {
                let windows = known_folder(&FOLDERID_Windows)?;
                match Path::new(&windows).components().next()? {
                    Component::Prefix(p) => {
                        let drive: Vec<u16> = p.as_os_str().encode_wide().collect();
                        Some(OsString::from_wide(&drive))
                    }
                    _ => None,
                }
            }
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
}
