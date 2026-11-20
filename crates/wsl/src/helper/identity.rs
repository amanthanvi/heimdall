//! What the helper reports in its hello (design U3 §2): its uid and account, the
//! distribution it runs in, whether Windows interop works, and `/etc/wsl.conf`'s
//! `appendWindowsPath`.

use std::path::Path;

/// The helper's facts, before they become a [`crate::proto::Hello`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// `geteuid()`.
    pub uid: u32,
    /// `getpwuid_r(uid)` name.
    pub account: String,
    /// `$WSL_DISTRO_NAME`.
    pub distribution: Option<String>,
    /// Windows interop is enabled.
    pub interop: bool,
    /// `/etc/wsl.conf` `[interop] appendWindowsPath`; `None` when the file does not parse.
    pub append_windows_path: Option<bool>,
}

/// The effective uid of this process.
#[cfg(unix)]
#[must_use]
pub fn effective_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// The effective uid of this process (the helper runs on Linux only).
#[cfg(not(unix))]
#[must_use]
pub fn effective_uid() -> u32 {
    0
}

/// Whether the interop binfmt entry is registered.
#[must_use]
pub fn interop_enabled() -> bool {
    ["WSLInterop", "WSLInterop-late"]
        .iter()
        .any(|n| Path::new("/proc/sys/fs/binfmt_misc").join(n).exists())
}

/// `[interop] appendWindowsPath` of a `wsl.conf` text: `Some(true)` when the key is absent
/// (WSL's default), `None` when the text does not parse (a line that is neither a comment,
/// a section header nor `key = value`, an unterminated header, or a non-boolean value).
#[must_use]
pub fn parse_append_windows_path(text: &str) -> Option<bool> {
    let mut section = String::new();
    let mut value = true;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            section = rest.strip_suffix(']')?.trim().to_ascii_lowercase();
            continue;
        }
        let (key, val) = line.split_once('=')?;
        if section == "interop" && key.trim().eq_ignore_ascii_case("appendWindowsPath") {
            // A trailing comment is not part of the value.
            let val = val.split('#').next().unwrap_or("").trim().trim_matches('"');
            value = match val.to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => return None,
            };
        }
    }
    Some(value)
}

/// `appendWindowsPath` from `/etc/wsl.conf`; an absent file is the default (`true`), an
/// unreadable one is `None`.
#[must_use]
pub fn read_append_windows_path() -> Option<bool> {
    match std::fs::read_to_string("/etc/wsl.conf") {
        Ok(text) => parse_append_windows_path(&text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(true),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_windows_path_reads_the_interop_section_only() {
        assert_eq!(parse_append_windows_path(""), Some(true));
        assert_eq!(
            parse_append_windows_path("[interop]\nenabled=true\nappendWindowsPath = false\n"),
            Some(false)
        );
        assert_eq!(
            parse_append_windows_path("# c\n[boot]\nappendWindowsPath=false\n[interop]\n"),
            Some(true)
        );
        assert_eq!(
            parse_append_windows_path("[interop]\nappendWindowsPath=TRUE # why\n"),
            Some(true)
        );
        for bad in [
            "[interop\nappendWindowsPath=false",
            "[interop]\nappendWindowsPath=maybe",
            "[interop]\nnot a pair",
        ] {
            assert_eq!(parse_append_windows_path(bad), None, "{bad}");
        }
    }
}
