//! The exact data of each login entry, and the reverse reading (M04 U1; ADR-0010 §1
//! item 2, §6 item 1).
//!
//! Pure text, on every platform, so the three renderings are unit-tested wherever the
//! workspace builds. An entry is **owned** when its data equals, byte for byte, what
//! Heimdall renders from the command it names: a parse followed by a re-render must give
//! the original back ([`owned_run_value`], [`owned_plist`], [`owned_unit`]). The
//! executable path is the one free variable, so an entry written by an older install at
//! another path is still recognized as Heimdall's own and may be replaced or removed,
//! while any hand edit (an added argument, another key, another label) is not owned and
//! is never touched.

use std::path::{Path, PathBuf};

/// The arguments every login entry runs: `service run --login` (ADR-0010 §1 item 2).
pub const LOGIN_ARGS: [&str; 3] = ["service", "run", "--login"];

/// Prefix of the Windows Run value's name: `Heimdall-<installation token>`.
pub const RUN_VALUE_PREFIX: &str = "Heimdall-";

/// Prefix of the macOS LaunchAgent label: `<prefix><installation token>`.
pub const LAUNCH_AGENT_LABEL_PREFIX: &str = "io.github.amanthanvi.heimdall.";

/// The systemd user unit's file name (one per user).
pub const SYSTEMD_UNIT_NAME: &str = "heimdall.service";

/// The first line of the systemd unit: names the file's owner and its format.
const UNIT_MARKER: &str = "# heimdall-login-entry/1";

/// What a login entry runs: the absolute executable, then [`LOGIN_ARGS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginCommand {
    /// The absolute path of the `heimdall` executable.
    pub exe: PathBuf,
}

/// A command that cannot be rendered into an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct RenderError(pub &'static str);

impl LoginCommand {
    /// A command for `exe`.
    ///
    /// # Errors
    /// The path is relative, is not UTF-8, or holds a control character or a double
    /// quote (none of the three entry formats can carry it without a second layer of
    /// escaping that this build does not offer).
    pub fn new(exe: &Path) -> Result<Self, RenderError> {
        if !exe.is_absolute() {
            return Err(RenderError("the executable path is not absolute"));
        }
        let text = exe
            .to_str()
            .ok_or(RenderError("the executable path is not UTF-8"))?;
        if text.chars().any(|c| c.is_control() || c == '"') {
            return Err(RenderError(
                "the executable path holds a control character or a double quote",
            ));
        }
        Ok(Self {
            exe: exe.to_owned(),
        })
    }

    /// The path as text (validated by [`LoginCommand::new`]).
    fn text(&self) -> &str {
        self.exe.to_str().unwrap_or_default()
    }
}

// --- Windows Run value ---------------------------------------------------------------------

/// The Run value's name for an installation token.
#[must_use]
pub fn run_value_name(token: &str) -> String {
    format!("{RUN_VALUE_PREFIX}{token}")
}

/// The Run value's data: `"<exe>" service run --login`.
#[must_use]
pub fn run_value_data(command: &LoginCommand) -> String {
    format!("\"{}\" {}", command.text(), LOGIN_ARGS.join(" "))
}

/// Read a Run value's data back into its command, only when it is exactly Heimdall's.
#[must_use]
pub fn owned_run_value(data: &str) -> Option<LoginCommand> {
    let rest = data.strip_prefix('"')?;
    let (exe, _tail) = rest.split_once('"')?;
    let command = LoginCommand::new(Path::new(exe)).ok()?;
    (run_value_data(&command) == data).then_some(command)
}

// --- macOS LaunchAgent ---------------------------------------------------------------------

/// The LaunchAgent label for an installation token.
#[must_use]
pub fn launch_agent_label(token: &str) -> String {
    format!("{LAUNCH_AGENT_LABEL_PREFIX}{token}")
}

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            other => out.push(other),
        }
    }
    out
}

fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// The LaunchAgent property list: `RunAtLoad`, and `KeepAlive` on an unsuccessful exit
/// only (`SuccessfulExit` false), so a clean exit (including `--login` yielding to a
/// running instance) is never restarted.
#[must_use]
pub fn launch_agent_plist(label: &str, command: &LoginCommand) -> String {
    let args: String = LOGIN_ARGS
        .iter()
        .map(|a| format!("\t\t<string>{a}</string>\n"))
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n\
         <dict>\n\
         \t<key>Label</key>\n\
         \t<string>{label}</string>\n\
         \t<key>ProgramArguments</key>\n\
         \t<array>\n\
         \t\t<string>{exe}</string>\n\
         {args}\
         \t</array>\n\
         \t<key>RunAtLoad</key>\n\
         \t<true/>\n\
         \t<key>KeepAlive</key>\n\
         \t<dict>\n\
         \t\t<key>SuccessfulExit</key>\n\
         \t\t<false/>\n\
         \t</dict>\n\
         </dict>\n\
         </plist>\n",
        label = xml_escape(label),
        exe = xml_escape(command.text()),
    )
}

/// The text between the first `<string>` and `</string>` after `anchor`.
fn string_after<'a>(text: &'a str, anchor: &str) -> Option<&'a str> {
    let at = text.find(anchor)? + anchor.len();
    let rest = &text[at..];
    let open = rest.find("<string>")? + "<string>".len();
    let close = rest[open..].find("</string>")?;
    Some(&rest[open..open + close])
}

/// Read a property list back into its command, only when it is exactly Heimdall's for
/// `label`.
#[must_use]
pub fn owned_plist(text: &str, label: &str) -> Option<LoginCommand> {
    let found_label = xml_unescape(string_after(text, "<key>Label</key>")?);
    let exe = xml_unescape(string_after(text, "<key>ProgramArguments</key>")?);
    let command = LoginCommand::new(Path::new(&exe)).ok()?;
    (found_label == label && launch_agent_plist(label, &command) == text).then_some(command)
}

// --- Linux systemd user unit ---------------------------------------------------------------

/// `ExecStart` quoting: the path in double quotes, with the three characters systemd
/// expands inside them escaped (`\` and the specifier `%` and variable `$` markers).
fn systemd_quote(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 2);
    out.push('"');
    for c in path.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn systemd_unquote(quoted: &str) -> Option<String> {
    let inner = quoted.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('\\', Some('\\')) | ('%', Some('%')) | ('$', Some('$')) => {
                out.push(c);
                chars.next();
            }
            ('\\' | '%' | '$', _) => return None,
            (other, _) => out.push(other),
        }
    }
    Some(out)
}

/// The systemd user unit. `Restart=on-failure` mirrors the LaunchAgent's `KeepAlive`: a
/// clean exit is not restarted. No `--now`, no lingering: it starts at the next login of
/// the user's manager.
#[must_use]
pub fn systemd_unit(command: &LoginCommand) -> String {
    format!(
        "{UNIT_MARKER}\n\
         [Unit]\n\
         Description=Heimdall per-user runtime (started at login)\n\
         \n\
         [Service]\n\
         ExecStart={exec} {args}\n\
         Restart=on-failure\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        exec = systemd_quote(command.text()),
        args = LOGIN_ARGS.join(" "),
    )
}

/// Read a unit back into its command, only when it is exactly Heimdall's.
#[must_use]
pub fn owned_unit(text: &str) -> Option<LoginCommand> {
    let line = text.lines().find(|l| l.starts_with("ExecStart="))?;
    let value = line.strip_prefix("ExecStart=")?;
    let rest = value.strip_prefix('"')?;
    // The closing quote is the first unescaped one: escapes are `\\`, `%%`, `$$`, and a
    // double quote never occurs inside (`LoginCommand::new`).
    let end = rest.find('"')?;
    let exe = systemd_unquote(&value[..end + 2])?;
    let command = LoginCommand::new(Path::new(&exe)).ok()?;
    (systemd_unit(&command) == text).then_some(command)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn cmd(path: &str) -> LoginCommand {
        let p = if cfg!(windows) {
            PathBuf::from(format!("C:{path}"))
        } else {
            PathBuf::from(path)
        };
        LoginCommand::new(&p).unwrap()
    }

    /// The three renderings are what ADR-0010 §1 item 2 and §6 item 1 name, and each is
    /// read back as Heimdall's own only when byte-identical to a re-render. A hand edit,
    /// another label, a foreign command and a path that cannot be rendered are all not
    /// owned.
    #[test]
    fn each_rendering_round_trips_and_only_exact_data_is_owned() {
        let c = cmd("/opt/heim dall/bin/heimdall");
        // Run value.
        let data = run_value_data(&c);
        assert_eq!(
            data,
            format!("\"{}\" service run --login", c.exe.to_str().unwrap())
        );
        assert_eq!(run_value_name("0123abcd"), "Heimdall-0123abcd");
        assert_eq!(owned_run_value(&data), Some(c.clone()));
        for edited in [
            format!("{data} --extra"),
            format!("{data} "),
            data.replace("service run", "service  run"),
            data.replacen('"', "", 1),
            String::new(),
            "C:\\other\\tool.exe --flag".to_owned(),
        ] {
            assert_eq!(owned_run_value(&edited), None, "{edited:?}");
        }
        // LaunchAgent.
        let label = launch_agent_label("0123abcd");
        assert_eq!(label, "io.github.amanthanvi.heimdall.0123abcd");
        let plist = launch_agent_plist(&label, &c);
        assert!(plist.contains("<key>SuccessfulExit</key>\n\t\t<false/>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert_eq!(owned_plist(&plist, &label), Some(c.clone()));
        assert_eq!(owned_plist(&plist, "io.example.other"), None);
        for edited in [
            plist.replace("<false/>", "<true/>"),
            plist.replace("--login", "--login</string>\n\t\t<string>--evil"),
            format!("{plist}<!-- edited -->\n"),
            plist.replace("RunAtLoad", "RunAtLoads"),
        ] {
            assert_eq!(owned_plist(&edited, &label), None);
        }
        // systemd unit.
        let unit = systemd_unit(&c);
        assert!(unit.starts_with("# heimdall-login-entry/1\n"));
        assert!(unit.contains("WantedBy=default.target"));
        assert!(unit.contains("Restart=on-failure"));
        assert_eq!(owned_unit(&unit), Some(c.clone()));
        for edited in [
            unit.replace("Restart=on-failure", "Restart=always"),
            unit.replace("--login", "--login --evil"),
            format!("{unit}ExecStartPost=/bin/true\n"),
            "[Service]\nExecStart=/bin/true\n".to_owned(),
        ] {
            assert_eq!(owned_unit(&edited), None);
        }
    }

    /// Characters that need escaping in one of the formats survive a round trip; the
    /// ones no format can carry are refused up front, never rendered.
    #[test]
    fn awkward_paths_escape_or_are_refused() {
        let c = cmd("/a b/c&d<e>f/100%/$HOME/back\\slash/heimdall");
        let plist = launch_agent_plist("l", &c);
        assert!(plist.contains("c&amp;d&lt;e&gt;f"));
        assert_eq!(owned_plist(&plist, "l"), Some(c.clone()));
        let unit = systemd_unit(&c);
        assert!(unit.contains("100%%/$$HOME/back\\\\slash"));
        assert_eq!(owned_unit(&unit), Some(c.clone()));
        assert_eq!(owned_run_value(&run_value_data(&c)), Some(c));
        for bad in ["relative/heimdall", "/a\"b/heimdall", "/a\nb/heimdall"] {
            assert!(LoginCommand::new(Path::new(bad)).is_err(), "{bad:?}");
        }
    }
}
