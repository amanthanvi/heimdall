//! ⟨M06 U5a⟩ The route helper's alias and the catalog pin file (ADR-0012 §5.2, §5.3;
//! m06-plan U5a). Pure: text only.
//!
//! **The one ADR-0010 §5(b) exception** ([`HelperRoute`], rendered as
//! [`crate::render::Section::Helper`]). A destination with more than one approved route, or
//! any Iroh route, renders after its `User` line:
//!
//! ```text
//!     ProxyCommand "<abs heimdall>" route connect --destination <id> --account <User> --endpoint "<IdentityAgent>"
//!     HostKeyAlias hm-dest-<id>
//!     UserKnownHostsFile "<pin file>"
//!     GlobalKnownHostsFile none
//!     KnownHostsCommand none
//!     StrictHostKeyChecking yes
//!     VerifyHostKeyDNS no
//!     UpdateHostKeys no
//!     CheckHostIP no
//! ```
//!
//! * **Typed inputs only.** The program is an absolute path, the destination an ID, the
//!   account the section's own `User`, and the endpoint the section's own `IdentityAgent`
//!   (absolute: the helper takes it literally). No host, port, command or route text is ever
//!   rendered into the command: the helper reads the approved routes from the catalog.
//! * **Quoting.** OpenSSH runs a `ProxyCommand` through a shell (`/bin/sh -c exec …`; on
//!   Windows, the in-box client's own spawn), after expanding its `%` tokens. The program and
//!   the endpoint are double-quoted, and any character a POSIX shell or `cmd.exe` would read
//!   inside double quotes (`$`, `` ` ``, `\`, `!`, `^`, `&`, `|`, `<`, `>`, `;`) or that
//!   OpenSSH would expand (`%`) is refused, never escaped. The destination ID and the
//!   account are tokens without spaces.
//! * **The catalog pin.** `HostKeyAlias hm-dest-<id>` with the pin file, and the host-trust
//!   settings ADR-0012 §5.2 requires to hold **effectively** for a projected client:
//!   `StrictHostKeyChecking yes` and catalog-only trust. P states them so that, with nothing
//!   earlier in the user's configuration overriding them, the alias verifies; an earlier
//!   override is caught by the `ssh -G` verification (`heimdall_registry::routes`). A
//!   helper alias never multiplexes unless through the binding's own mux path.
//!
//! [`render_pin_file`] renders the pin file: `hm-dest-<id> <type> <base64>` lines, sorted.

use crate::render::{PathKind, PathStyle, RenderError, RenderPath, check_user};

/// The helper's subcommand words, after the program.
pub const HELPER_SUBCOMMAND: [&str; 2] = ["route", "connect"];

/// The `HostKeyAlias` prefix of a destination's catalog pin.
pub const HOST_KEY_ALIAS_PREFIX: &str = "hm-dest-";

/// Characters refused in the helper's quoted values (module docs), besides those
/// [`RenderPath`] already refuses (`"`, `${`, control characters).
const SHELL_REFUSED: &[char] = &['$', '`', '\\', '!', '^', '&', '|', '<', '>', ';', '%'];

/// A destination ID as the helper's `--destination` and the pin's `hm-dest-<id>`:
/// `[A-Za-z0-9._-]`, not starting with `-`, at most 247 bytes.
fn destination_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() + HOST_KEY_ALIAS_PREFIX.len() <= 255
        && !id.starts_with('-')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The helper route of one alias (ADR-0012 §5.3): Heimdall's own executable, the destination
/// and its pin file.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HelperRoute {
    program: RenderPath,
    destination: String,
    pin_file: RenderPath,
}

impl HelperRoute {
    /// Validate the helper's inputs: `program` an absolute file path (never `~`, never a
    /// pipe) free of [`SHELL_REFUSED`] characters, `destination` a plain ID, `pin_file` a
    /// file path (never a pipe) free of `%`.
    ///
    /// # Errors
    /// [`RenderError::RefusedValue`] (`helper_program`, `destination`, `pin_file`).
    pub fn new(
        program: RenderPath,
        destination: &str,
        pin_file: RenderPath,
    ) -> Result<HelperRoute, RenderError> {
        if !program.is_absolute_file() || program.as_str().contains(SHELL_REFUSED) {
            return Err(RenderError::RefusedValue("helper_program"));
        }
        if !destination_ok(destination) {
            return Err(RenderError::RefusedValue("destination"));
        }
        if pin_file.kind == PathKind::Pipe || pin_file.as_str().contains('%') {
            return Err(RenderError::RefusedValue("pin_file"));
        }
        Ok(HelperRoute {
            program,
            destination: destination.to_owned(),
            pin_file,
        })
    }

    /// The destination ID.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }

    /// `hm-dest-<id>`.
    #[must_use]
    pub fn host_key_alias(&self) -> String {
        format!("{HOST_KEY_ALIAS_PREFIX}{}", self.destination)
    }

    /// The pin file.
    #[must_use]
    pub fn pin_file(&self) -> &RenderPath {
        &self.pin_file
    }
}

/// The `ProxyCommand` value for `route` with the section's `account` and `endpoint`, exactly
/// as P writes it (and as `ssh -G` prints it): `"<program>" route connect --destination <id>
/// --account <account> --endpoint "<endpoint>"`.
///
/// # Errors
/// [`RenderError::RefusedValue`]: a program or endpoint that does not fit `style`, an
/// endpoint that is `~`-relative or holds a refused character, or a refused account.
pub fn helper_command(
    route: &HelperRoute,
    account: &str,
    endpoint: &RenderPath,
    style: PathStyle,
) -> Result<String, RenderError> {
    check_user(account)?;
    if !route.program.fits(style) {
        return Err(RenderError::RefusedValue("helper_program"));
    }
    if !route.pin_file.fits(style) {
        return Err(RenderError::RefusedValue("pin_file"));
    }
    let endpoint_ok = endpoint.fits(style)
        && !endpoint.as_str().starts_with('~')
        && !endpoint.as_str().contains(SHELL_REFUSED);
    if !endpoint_ok {
        return Err(RenderError::RefusedValue("endpoint"));
    }
    Ok(format!(
        "\"{}\" {} {} --destination {} --account {account} --endpoint \"{}\"",
        route.program.as_str(),
        HELPER_SUBCOMMAND[0],
        HELPER_SUBCOMMAND[1],
        route.destination,
        endpoint.as_str(),
    ))
}

/// The lines a helper section carries after `User` (module docs), each ending in `\n`.
///
/// # Errors
/// As [`helper_command`].
pub(crate) fn helper_lines(
    route: &HelperRoute,
    account: &str,
    endpoint: &RenderPath,
    style: PathStyle,
) -> Result<String, RenderError> {
    let command = helper_command(route, account, endpoint, style)?;
    Ok(format!(
        "    ProxyCommand {command}\n    HostKeyAlias {}\n    UserKnownHostsFile {}\n    \
         GlobalKnownHostsFile none\n    KnownHostsCommand none\n    StrictHostKeyChecking yes\n    \
         VerifyHostKeyDNS no\n    UpdateHostKeys no\n    CheckHostIP no\n",
        route.host_key_alias(),
        route.pin_file.ssh_quoted(),
    ))
}

/// The pin file (ADR-0012 §5.1, §5.2): one `hm-dest-<id> <type> <base64>` line per
/// catalog-pinned host key, sorted, LF line endings. `pins` holds `(destination ID, OpenSSH
/// public key line)`; a key's comment is dropped.
///
/// # Errors
/// [`RenderError::RefusedValue`] (`destination`, `host_key`): an ID that cannot be a pin
/// name, or a key line that is not one plain key of a type that can be the only trust source
/// (a certificate, DSA, a security-key or unknown type).
pub fn render_pin_file(pins: &[(String, String)]) -> Result<Vec<u8>, RenderError> {
    let mut lines = Vec::with_capacity(pins.len());
    for (destination, key) in pins {
        if !destination_ok(destination) {
            return Err(RenderError::RefusedValue("destination"));
        }
        if key.chars().any(char::is_control) {
            return Err(RenderError::RefusedValue("host_key"));
        }
        let mut words = key.split_ascii_whitespace();
        let (Some(key_type), Some(blob)) = (words.next(), words.next()) else {
            return Err(RenderError::RefusedValue("host_key"));
        };
        let pinnable = matches!(
            key_type,
            "ssh-ed25519"
                | "ecdsa-sha2-nistp256"
                | "ecdsa-sha2-nistp384"
                | "ecdsa-sha2-nistp521"
                | "ssh-rsa"
        );
        let blob_ok = !blob.is_empty()
            && blob
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
        if !pinnable || !blob_ok {
            return Err(RenderError::RefusedValue("host_key"));
        }
        lines.push(format!(
            "{HOST_KEY_ALIAS_PREFIX}{destination} {key_type} {blob}\n"
        ));
    }
    lines.sort();
    lines.dedup();
    Ok(lines.concat().into_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::render::{
        AliasName, DEFAULT_MANAGED_IDENTITY_FORM, HostName, ManagedAlias, Section, render_sections,
    };

    fn existing(alias: &str, host: &str, agent: &str) -> ManagedAlias {
        ManagedAlias {
            alias: AliasName::parse(alias).unwrap(),
            hostname: HostName::parse(host).unwrap(),
            port: Some(2222),
            user: "deploy".into(),
            identity_agent: Some(RenderPath::unix(Path::new(agent)).unwrap()),
            identity_files: vec![RenderPath::unix(Path::new("~/.ssh/id_lab.pub")).unwrap()],
            identities_only: true,
        }
    }

    fn helper(dest: &str) -> HelperRoute {
        HelperRoute::new(
            RenderPath::unix(Path::new("/opt/heimdall/bin/heimdall")).unwrap(),
            dest,
            RenderPath::unix(Path::new("/home/u/.local/state/heimdall/pins/known_hosts")).unwrap(),
        )
        .unwrap()
    }

    fn render(sections: &[Section], style: PathStyle) -> String {
        String::from_utf8(render_sections(sections, style, DEFAULT_MANAGED_IDENTITY_FORM).unwrap())
            .unwrap()
    }

    /// Golden, one route (ADR-0012 §5.3): a destination with one direct route, and one with
    /// one jump route, keep their native rendering byte for byte (M02/M04).
    #[test]
    fn golden_one_route_keeps_the_native_rendering() {
        let direct = render(
            &[Section::ExistingAccess(existing(
                "lab",
                "10.0.0.2",
                "/run/agent.sock",
            ))],
            PathStyle::Unix,
        );
        assert_eq!(
            direct,
            "# heimdall managed ssh configuration (generated; do not edit)\n\
             \n\
             Host lab\n\
             \x20   HostName 10.0.0.2\n\
             \x20   Port 2222\n\
             \x20   User deploy\n\
             \x20   IdentityAgent \"/run/agent.sock\"\n\
             \x20   IdentityFile \"~/.ssh/id_lab.pub\"\n\
             \x20   IdentitiesOnly yes\n"
        );
        let jump = render(
            &[Section::Routed {
                jump: AliasName::parse("bastion").unwrap(),
                section: Box::new(Section::ExistingAccess(existing(
                    "lab",
                    "10.0.0.2",
                    "/run/agent.sock",
                ))),
            }],
            PathStyle::Unix,
        );
        assert_eq!(
            jump,
            "# heimdall managed ssh configuration (generated; do not edit)\n\
             \n\
             Host lab\n\
             \x20   HostName 10.0.0.2\n\
             \x20   Port 2222\n\
             \x20   User deploy\n\
             \x20   ProxyJump bastion\n\
             \x20   IdentityAgent \"/run/agent.sock\"\n\
             \x20   IdentityFile \"~/.ssh/id_lab.pub\"\n\
             \x20   IdentitiesOnly yes\n"
        );
        for not_native in ["ProxyCommand", "HostKeyAlias", "StrictHostKeyChecking"] {
            assert!(!direct.contains(not_native) && !jump.contains(not_native));
        }
    }

    /// Golden, several routes (ADR-0012 §5.2, §5.3): the helper's `ProxyCommand` with typed
    /// inputs only, the catalog pin and the effective-trust settings, for an existing-access
    /// and a managed-certificate section.
    #[test]
    fn golden_several_routes_render_the_helper() {
        let text = render(
            &[Section::Helper {
                route: helper("lab"),
                section: Box::new(Section::ExistingAccess(existing(
                    "lab",
                    "10.0.0.2",
                    "/run/user/1000/heimdall/agent.sock",
                ))),
            }],
            PathStyle::Unix,
        );
        assert_eq!(
            text,
            "# heimdall managed ssh configuration (generated; do not edit)\n\
             \n\
             Host lab\n\
             \x20   HostName 10.0.0.2\n\
             \x20   Port 2222\n\
             \x20   User deploy\n\
             \x20   ProxyCommand \"/opt/heimdall/bin/heimdall\" route connect --destination lab --account deploy --endpoint \"/run/user/1000/heimdall/agent.sock\"\n\
             \x20   HostKeyAlias hm-dest-lab\n\
             \x20   UserKnownHostsFile \"/home/u/.local/state/heimdall/pins/known_hosts\"\n\
             \x20   GlobalKnownHostsFile none\n\
             \x20   KnownHostsCommand none\n\
             \x20   StrictHostKeyChecking yes\n\
             \x20   VerifyHostKeyDNS no\n\
             \x20   UpdateHostKeys no\n\
             \x20   CheckHostIP no\n\
             \x20   IdentityAgent \"/run/user/1000/heimdall/agent.sock\"\n\
             \x20   IdentityFile \"~/.ssh/id_lab.pub\"\n\
             \x20   IdentitiesOnly yes\n\
             \x20   ControlMaster no\n\
             \x20   ControlPath none\n"
        );
        let managed = render(
            &[Section::Helper {
                route: helper("lab"),
                section: Box::new(Section::ManagedCertificate {
                    alias: AliasName::parse("lab").unwrap(),
                    hostname: HostName::parse("10.0.0.2").unwrap(),
                    port: None,
                    user: "deploy".into(),
                    endpoint: RenderPath::unix(Path::new("/run/hm/env-signing.sock")).unwrap(),
                    key_pub: RenderPath::unix(Path::new("/d/managed/lab/key.pub")).unwrap(),
                    cert: RenderPath::unix(Path::new("/d/managed/lab/cert.pub")).unwrap(),
                    control_path: Some(RenderPath::unix(Path::new("/run/hm/mux/lab")).unwrap()),
                }),
            }],
            PathStyle::Unix,
        );
        assert_eq!(
            managed,
            "# heimdall managed ssh configuration (generated; do not edit)\n\
             \n\
             Host lab\n\
             \x20   HostName 10.0.0.2\n\
             \x20   User deploy\n\
             \x20   ProxyCommand \"/opt/heimdall/bin/heimdall\" route connect --destination lab --account deploy --endpoint \"/run/hm/env-signing.sock\"\n\
             \x20   HostKeyAlias hm-dest-lab\n\
             \x20   UserKnownHostsFile \"/home/u/.local/state/heimdall/pins/known_hosts\"\n\
             \x20   GlobalKnownHostsFile none\n\
             \x20   KnownHostsCommand none\n\
             \x20   StrictHostKeyChecking yes\n\
             \x20   VerifyHostKeyDNS no\n\
             \x20   UpdateHostKeys no\n\
             \x20   CheckHostIP no\n\
             \x20   IdentityAgent \"/run/hm/env-signing.sock\"\n\
             \x20   IdentitiesOnly yes\n\
             \x20   IdentityFile \"/d/managed/lab/cert.pub\"\n\
             \x20   ControlMaster no\n\
             \x20   ControlPath \"/run/hm/mux/lab\"\n"
        );
        assert!(!managed.contains("ForwardAgent") && !managed.contains("ProxyJump"));
    }

    /// WSL Mode A (m06-plan U5a): the Windows `ssh.exe` reads a Windows-style P, so the
    /// helper's program is a drive path with `/` separators, quoted, and the endpoint the
    /// environment's pipe as `//./pipe/…`. Mode B's Linux alias is the Unix rendering above.
    /// The native `ProxyCommand` execution by the in-box client is platform-only (Windows).
    #[test]
    fn golden_windows_helper_command_quotes_the_program_and_the_pipe() {
        let route = HelperRoute::new(
            RenderPath::windows(Path::new(
                r"C:\Users\u\AppData\Local\Programs\Heimdall (beta)\heimdall.exe",
            ))
            .unwrap(),
            "lab",
            RenderPath::windows(Path::new(
                r"C:\Users\u\AppData\Local\heimdall\pins\known_hosts",
            ))
            .unwrap(),
        )
        .unwrap();
        let text = render(
            &[Section::Helper {
                route,
                section: Box::new(Section::ManagedCertificate {
                    alias: AliasName::parse("lab").unwrap(),
                    hostname: HostName::parse("10.0.0.2").unwrap(),
                    port: None,
                    user: "deploy".into(),
                    endpoint: RenderPath::pipe(r"\\.\pipe\heimdall-0123abcd-signing").unwrap(),
                    key_pub: RenderPath::windows(Path::new(r"C:\d\managed\lab\key.pub")).unwrap(),
                    cert: RenderPath::windows(Path::new(r"C:\d\managed\lab\cert.pub")).unwrap(),
                    control_path: None,
                }),
            }],
            PathStyle::Windows,
        );
        assert!(
            text.contains(
                "    ProxyCommand \"C:/Users/u/AppData/Local/Programs/Heimdall (beta)/heimdall.exe\" \
                 route connect --destination lab --account deploy --endpoint \"//./pipe/heimdall-0123abcd-signing\"\n"
            ),
            "{text}"
        );
        assert!(text.contains(
            "    UserKnownHostsFile \"C:/Users/u/AppData/Local/heimdall/pins/known_hosts\"\n"
        ));
        assert!(text.contains("    IdentityAgent \"//./pipe/heimdall-0123abcd-signing\"\n"));
        assert!(text.contains("    ControlPath none\n"));
        // A Unix program in a Windows P is refused.
        let unix = Section::Helper {
            route: helper("lab"),
            section: Box::new(Section::ExistingAccess(existing(
                "lab", "10.0.0.2", "/a.sock",
            ))),
        };
        assert!(
            render_sections(&[unix], PathStyle::Windows, DEFAULT_MANAGED_IDENTITY_FORM).is_err()
        );
    }

    /// ADR-0012 §5.3: only typed inputs reach the command; every value a shell or OpenSSH
    /// would read differently is refused, never escaped; a helper never wraps a route.
    #[test]
    fn helper_refuses_untyped_or_shell_active_values() {
        let unix = |p: &str| RenderPath::unix(Path::new(p)).unwrap();
        let pins = || unix("/p/known_hosts");
        for bad in [
            "/opt/$x/heimdall",
            "/opt/`id`/heimdall",
            "/opt/a;b/heimdall",
            "/opt/50%/h",
        ] {
            assert_eq!(
                HelperRoute::new(unix(bad), "lab", pins()),
                Err(RenderError::RefusedValue("helper_program")),
                "{bad}"
            );
        }
        assert_eq!(
            HelperRoute::new(unix("~/bin/heimdall"), "lab", pins()),
            Err(RenderError::RefusedValue("helper_program"))
        );
        for bad in ["-lab", "a:b", "a b", "a/b", ""] {
            assert!(
                HelperRoute::new(unix("/h"), bad, pins()).is_err(),
                "{bad:?}"
            );
        }
        assert_eq!(
            HelperRoute::new(unix("/h"), "lab", unix("/p/%h")),
            Err(RenderError::RefusedValue("pin_file"))
        );
        let route = helper("lab");
        for bad in ["~/agent.sock", "/run/$USER/a.sock", "/run/a|b.sock"] {
            assert_eq!(
                helper_command(&route, "deploy", &unix(bad), PathStyle::Unix),
                Err(RenderError::RefusedValue("endpoint")),
                "{bad}"
            );
        }
        assert!(
            helper_command(
                &route,
                "-oProxyCommand=x",
                &unix("/a.sock"),
                PathStyle::Unix
            )
            .is_err()
        );
        // No endpoint (an existing-access alias without `IdentityAgent`): refused.
        let mut no_agent = existing("lab", "10.0.0.2", "/a.sock");
        no_agent.identity_agent = None;
        let s = Section::Helper {
            route: route.clone(),
            section: Box::new(Section::ExistingAccess(no_agent)),
        };
        assert_eq!(
            render_sections(&[s], PathStyle::Unix, DEFAULT_MANAGED_IDENTITY_FORM),
            Err(RenderError::RefusedValue("identity_agent"))
        );
        // Never around a route, and never inside one.
        let inner = Section::Routed {
            jump: AliasName::parse("bastion").unwrap(),
            section: Box::new(Section::ExistingAccess(existing("lab", "h", "/a.sock"))),
        };
        let s = Section::Helper {
            route: route.clone(),
            section: Box::new(inner),
        };
        assert_eq!(
            render_sections(&[s], PathStyle::Unix, DEFAULT_MANAGED_IDENTITY_FORM),
            Err(RenderError::RefusedValue("route"))
        );
        let s = Section::Routed {
            jump: AliasName::parse("bastion").unwrap(),
            section: Box::new(Section::Helper {
                route,
                section: Box::new(Section::ExistingAccess(existing("lab", "h", "/a.sock"))),
            }),
        };
        assert_eq!(
            render_sections(&[s], PathStyle::Unix, DEFAULT_MANAGED_IDENTITY_FORM),
            Err(RenderError::RefusedValue("jump"))
        );
    }

    #[test]
    fn pin_file_lines_are_sorted_plain_keys() {
        let text = render_pin_file(&[
            (
                "lab".into(),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB comment".into(),
            ),
            ("bastion".into(), "ecdsa-sha2-nistp256 AAAAE2Vj+/=".into()),
            (
                "lab".into(),
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB".into(),
            ),
        ])
        .unwrap();
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "hm-dest-bastion ecdsa-sha2-nistp256 AAAAE2Vj+/=\n\
             hm-dest-lab ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB\n"
        );
        for (d, k) in [
            ("a:b", "ssh-ed25519 AAAA"),
            ("lab", "ssh-ed25519-cert-v01@openssh.com AAAA"),
            ("lab", "ssh-dss AAAA"),
            ("lab", "ssh-ed25519"),
            ("lab", "ssh-ed25519 AA\nAA"),
        ] {
            assert!(
                render_pin_file(&[(d.into(), k.into())]).is_err(),
                "{d} {k:?}"
            );
        }
    }
}
