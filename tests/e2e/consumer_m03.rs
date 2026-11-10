//! M03 wave 2 (U8): consumer integration for managed pairs (m03-plan U8 "Tests"; ADR-0008
//! D8 item 2, D10 item 4; §17.4 item 7).
//!
//! Cargo test target `e2e_consumer_m03`, hosted by `heimdall`.
//!
//! * **Owned launches stay in the foreground.** The command line an owned launch runs is
//!   built by `heimdall_sshconf::render::{owned_ssh_arguments, check_owned_ssh_arguments}`,
//!   which `run` and `connect` call (`launch_flow::owned_ssh_args`). These tests check the
//!   argument vector and refusals, and run the real client's `ssh -G` (static: nothing
//!   connects) over the product's pins to show they win over an inherited configuration.
//! * **`connect`'s binding-endpoint options** (D10 item 4) are
//!   `heimdall_sshconf::render::managed_identity_options`, also checked through `ssh -G`
//!   (command-line values win, F1).
//! * **`connect` for an existing-access alias** runs through the real binary against a
//!   real runtime in a scratch `HEIMDALL_HOME`, with a stub `ssh` first on `PATH` that
//!   records its arguments: M02's launch, `ssh <alias>`, unchanged (Unix).
//!
//! The managed `connect` and `run` flows end to end (ensure, bind, launch with the binding
//! endpoint; the slot check and auto-materialize against the runtime's slot table) need
//! U6, U7 and U10: today `ensure` refuses a managed pair `driver_unavailable`.
//!
//! Every client gets only the isolation arguments (ADR-0007 §9) besides the product
//! command line under test (m03-plan §0.2).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, Stdio};

use heimdall_sshconf::render::{
    DEFAULT_MANAGED_IDENTITY_FORM, OWNED_LAUNCH_PINS, OwnedOptionConflict, PathStyle, RenderPath,
    check_owned_ssh_arguments, managed_identity_options, owned_ssh_arguments,
};
use heimdall_testkit::home::{ScratchHome, find_program};

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

/// `ssh <pins> <isolation> <extra> -G <alias> <command>` with the scratch home's client
/// environment (the decoy agent at `SSH_AUTH_SOCK`, the scratch `HOME`), after the
/// default-identity guard; the effective configuration's lines.
fn effective(
    home: &ScratchHome,
    pins: bool,
    extra: &[String],
    alias: &str,
    command: Option<&str>,
) -> (bool, Vec<String>) {
    home.check_alias(alias).unwrap();
    let mut cmd = Command::new(find_program("ssh").expect("an ssh client"));
    if pins {
        cmd.args(OWNED_LAUNCH_PINS);
    }
    cmd.args(home.isolation_args())
        .args(extra)
        .arg("-G")
        .arg(alias)
        .args(command)
        .env("SSH_AUTH_SOCK", home.decoy_agent().endpoint().locator())
        .env("HOME", &home.git_home)
        .stdin(Stdio::null());
    let out = cmd.output().unwrap();
    heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
    let lines = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    (out.status.success(), lines)
}

/// The product's managed section for `work` (P, as the projection renders it, first in
/// the user configuration): the environment endpoint and the slot files in scratch, so
/// the default-identity guard admits the alias. `inherited` follows it.
fn with_p(home: &ScratchHome, inherited: &str) -> String {
    use heimdall_sshconf::render::{AliasName, HostName, Section, render_sections};
    let (style, file): (PathStyle, fn(&Path) -> RenderPath) = if cfg!(windows) {
        (PathStyle::Windows, |p| RenderPath::windows(p).unwrap())
    } else {
        (PathStyle::Unix, |p| RenderPath::unix(p).unwrap())
    };
    let slot = home.root.join("state").join("managed").join("dst-work");
    let endpoint = if cfg!(windows) {
        RenderPath::pipe(r"\\.\pipe\heimdall-tok-signing").unwrap()
    } else {
        file(&home.root.join("run").join("signing.sock"))
    };
    let section = Section::ManagedCertificate {
        alias: AliasName::parse("work").unwrap(),
        hostname: HostName::parse("127.0.0.1").unwrap(),
        port: None,
        user: "deploy".to_owned(),
        endpoint,
        key_pub: file(&slot.join("key.pub")),
        cert: file(&slot.join("cert.pub")),
        control_path: None,
    };
    let p = render_sections(&[section], style, DEFAULT_MANAGED_IDENTITY_FORM).unwrap();
    format!("{}{inherited}", String::from_utf8(p).unwrap())
}

fn has(lines: &[String], line: &str) -> bool {
    lines.iter().any(|l| l == line)
}

/// ADR-0008 D8 item 2: an owned launch (`connect`, and `run` of the verified client)
/// inserts `-o ForkAfterAuthentication=no -o ControlMaster=no -o ControlPath=none` right
/// after the program name, before the user's arguments; the real client reads them.
#[test]
fn owned_launch_pins_fork_after_authentication_no() {
    assert_eq!(
        OWNED_LAUNCH_PINS,
        [
            "-o",
            "ForkAfterAuthentication=no",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none"
        ]
    );
    // `run ssh <args>`: the pins first, then the user's arguments untouched.
    let user = os(&["-p", "2222", "-l", "deploy", "work", "uname", "-a"]);
    let argv = owned_ssh_arguments(&user).unwrap();
    assert_eq!(argv[..6], os(&OWNED_LAUNCH_PINS)[..]);
    assert_eq!(argv[6..], user[..]);
    // The real client's static view of the pinned command line.
    let home = ScratchHome::new();
    home.write_user_config(&with_p(&home, "")).unwrap();
    let (ok, lines) = effective(&home, true, &[], "work", Some("true"));
    assert!(ok, "{lines:?}");
    assert!(has(&lines, "forkafterauthentication no"), "{lines:?}");
    assert!(has(&lines, "controlmaster false"), "{lines:?}");
    assert!(
        !lines.iter().any(|l| l.starts_with("controlpath ")),
        "ControlPath none: {lines:?}"
    );
}

/// ADR-0008 D8 item 2, §17.4 item 7: the user's configuration sets
/// `ForkAfterAuthentication yes` (and its own multiplexing) for the alias; the owned
/// launch's pins are read first, so the connection stays in the launched process.
#[test]
fn inherited_fork_after_authentication_yes_stays_in_foreground() {
    let home = ScratchHome::new();
    let control = home.root.join("cm");
    home.write_user_config(&with_p(
        &home,
        &format!(
            "Host work\n  ForkAfterAuthentication yes\n  ControlMaster auto\n  ControlPath \"{}\"\n  ControlPersist yes\n",
            control.display()
        ),
    ))
    .unwrap();
    // Without the pins the inherited value applies (the control row); P already keeps
    // the user's multiplexing off for the managed alias (ADR-0008 D8 item 4).
    let (ok, lines) = effective(&home, false, &[], "work", Some("true"));
    assert!(ok, "{lines:?}");
    assert!(has(&lines, "forkafterauthentication yes"), "{lines:?}");
    assert!(has(&lines, "controlmaster false"), "{lines:?}");
    // With them: foreground, no master, no control path.
    let (ok, lines) = effective(&home, true, &[], "work", Some("true"));
    assert!(ok, "{lines:?}");
    assert!(has(&lines, "forkafterauthentication no"), "{lines:?}");
    assert!(has(&lines, "controlmaster false"), "{lines:?}");
    assert!(
        !lines.iter().any(|l| l.starts_with("controlpath ")),
        "{lines:?}"
    );
}

/// ADR-0008 D8 item 2: `run ssh -f …` (alone or bundled, before or after the
/// destination) is refused for an owned connection (`owned_connection_option_conflict`),
/// naming the argument by index only; `-f` inside the remote command is the command's.
#[test]
fn run_ssh_with_f_refused_for_owned_connection() {
    use OwnedOptionConflict::Fork;
    for (args, index) in [
        (&["-f", "work", "true"][..], 1),
        (&["-fN", "work"][..], 1),
        (&["-Nf", "work"][..], 1),
        (&["-p", "22", "-vfN", "work"][..], 3),
        (&["work", "-f", "true"][..], 2),
    ] {
        assert_eq!(
            check_owned_ssh_arguments(&os(args)),
            Err(Fork { index }),
            "{args:?}"
        );
        assert!(owned_ssh_arguments(&os(args)).is_err());
    }
    for args in [&["work", "tar", "-f", "x"][..], &["--", "work", "-f"][..]] {
        assert_eq!(check_owned_ssh_arguments(&os(args)), Ok(()), "{args:?}");
    }
    let shown = Fork { index: 2 }.to_string();
    assert!(
        shown.contains("argument 2") && !shown.contains("work"),
        "{shown}"
    );
}

/// ADR-0008 D8 item 2: `-M`, `-S`, `-O` and every `-o` form of
/// `ForkAfterAuthentication`, `ControlMaster`, `ControlPath` and `ControlPersist` are
/// refused for an owned connection.
#[test]
fn run_ssh_conflicting_control_options_refused() {
    use OwnedOptionConflict::{ControlCommand, ControlSocket, Master, Option as Opt};
    assert_eq!(
        check_owned_ssh_arguments(&os(&["-M", "work"])),
        Err(Master { index: 1 })
    );
    assert_eq!(
        check_owned_ssh_arguments(&os(&["-S", "/tmp/s", "work"])),
        Err(ControlSocket { index: 1 })
    );
    assert_eq!(
        check_owned_ssh_arguments(&os(&["-Snone", "work"])),
        Err(ControlSocket { index: 1 })
    );
    assert_eq!(
        check_owned_ssh_arguments(&os(&["-O", "check", "work"])),
        Err(ControlCommand { index: 1 })
    );
    for (value, keyword) in [
        ("ForkAfterAuthentication=yes", "ForkAfterAuthentication"),
        ("forkafterauthentication no", "ForkAfterAuthentication"),
        ("ControlMaster=auto", "ControlMaster"),
        ("CONTROLPATH=/tmp/%C", "ControlPath"),
        ("ControlPersist 10m", "ControlPersist"),
        (" ControlPersist=yes", "ControlPersist"),
    ] {
        assert_eq!(
            check_owned_ssh_arguments(&os(&["-o", value, "work"])),
            Err(Opt { index: 2, keyword }),
            "{value}"
        );
        assert_eq!(
            check_owned_ssh_arguments(&os(&[&format!("-o{value}"), "work"])),
            Err(Opt { index: 1, keyword }),
            "{value}"
        );
        assert_eq!(
            check_owned_ssh_arguments(&os(&["work", "-o", value])),
            Err(Opt { index: 3, keyword }),
            "after the destination: {value}"
        );
    }
    for fine in ["User=deploy", "ControlMasterx=yes", "ServerAliveInterval=5"] {
        assert_eq!(
            check_owned_ssh_arguments(&os(&["-o", fine, "work"])),
            Ok(())
        );
    }
}

/// ADR-0008 D10 item 4: `connect` names the **binding's** endpoint and files on the
/// command line (`-o IdentityAgent=…`, `-o IdentitiesOnly=yes`, the identity options of
/// the one form selector), so it works for any managed binding whatever P or the slot
/// say: the real client's static view takes them over an `IdentityAgent` the
/// configuration sets. (The flow that obtains the binding, `ensure` and `bind`, needs
/// U6/U10.)
#[test]
fn connect_uses_binding_endpoint_via_command_line() {
    let home = ScratchHome::new();
    let style = if cfg!(windows) {
        PathStyle::Windows
    } else {
        PathStyle::Unix
    };
    let file = |p: &Path| match style {
        PathStyle::Windows => RenderPath::windows(p).unwrap(),
        PathStyle::Unix => RenderPath::unix(p).unwrap(),
    };
    let binding = home.root.join("run").join("b").join("0123456789abcdef");
    let endpoint = if cfg!(windows) {
        RenderPath::pipe(r"\\.\pipe\heimdall-tok-b0123456789abcdef").unwrap()
    } else {
        file(&binding.join("agent.sock"))
    };
    let key_pub = file(&binding.join("key.pub"));
    let cert = file(&binding.join("cert-dst-work.pub"));
    let options = managed_identity_options(
        &endpoint,
        &key_pub,
        &cert,
        style,
        DEFAULT_MANAGED_IDENTITY_FORM,
    )
    .unwrap();
    let shown = |p: &RenderPath| format!("\"{}\"", p.as_str().replace('%', "%%"));
    assert_eq!(
        options,
        [
            "-o".to_owned(),
            format!("IdentityAgent={}", shown(&endpoint)),
            "-o".to_owned(),
            "IdentitiesOnly=yes".to_owned(),
            "-o".to_owned(),
            format!("IdentityFile={}", shown(&cert)),
        ],
        "the INT-Q10 form: the certificate as the identity file"
    );
    // The environment endpoint P names is overridden by the binding's on the command line.
    home.write_user_config(&with_p(&home, "")).unwrap();
    let (ok, lines) = effective(&home, true, &options, "work", Some("true"));
    assert!(ok, "{lines:?}");
    let agent = lines
        .iter()
        .find_map(|l| l.strip_prefix("identityagent "))
        .unwrap_or_default()
        .replace('\\', "/");
    assert!(
        agent.contains("0123456789abcdef"),
        "the binding endpoint wins: {agent}"
    );
    assert!(has(&lines, "identitiesonly yes"), "{lines:?}");
    let files: Vec<&String> = lines
        .iter()
        .filter(|l| l.starts_with("identityfile "))
        .collect();
    assert!(
        files
            .first()
            .is_some_and(|l| l.contains("cert-dst-work.pub")),
        "the binding's certificate is the first identity: {files:?}"
    );
}

// --- `connect` for an existing-access alias, through the binary (Unix) ------------------------

/// m03-plan U8: `connect` of an existing-access alias keeps M02's flow: no `ensure`, no
/// `bind`, and `ssh <alias>` launched with nothing added (no pins, no options). The
/// alias here is observed (defined in the user's configuration), the catalog's simplest
/// existing-access destination; the verified client is a stub first on `PATH` that
/// records its arguments.
#[cfg(unix)]
#[test]
fn connect_existing_access_pair_flow_unchanged_from_m02() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::Builder::new().prefix("hcm").tempdir().unwrap();
    let root = dir.path();
    let home = root.join("h");
    let user = root.join("u");
    let bin = root.join("bin");
    for d in [&user, &bin] {
        std::fs::create_dir(d).unwrap();
    }
    std::fs::write(user.join(".gitconfig"), b"").unwrap();
    let recorded = root.join("argv");
    let stub = bin.join("ssh");
    std::fs::write(
        &stub,
        "#!/bin/sh\nprintf '%s\\0' \"$@\" > \"$HM_U8_ARGV\"\nexit 0\n",
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let heimdall = std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_heimdall").to_owned());
    let run = |args: &[&str]| {
        let out = Command::new(&heimdall)
            .args(args)
            .env_clear()
            .env("HOME", &user)
            .env("HEIMDALL_HOME", &home)
            .env("HEIMDALL_TEST_ADAPTER", "prepare")
            .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", user.join(".gitconfig"))
            .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
            .env("HM_U8_ARGV", &recorded)
            .current_dir(root)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stdout));
        heimdall_testkit::assert_no_canary(&String::from_utf8_lossy(&out.stderr));
        out
    };
    struct Stop<'a>(&'a dyn Fn(&[&str]) -> std::process::Output);
    impl Drop for Stop<'_> {
        fn drop(&mut self) {
            let _ = (self.0)(&["service", "stop"]);
        }
    }
    let _stop = Stop(&run);
    let added = run(&[
        "--json",
        "--non-interactive",
        "destination",
        "add",
        "obs",
        "--observed",
    ]);
    assert_eq!(
        added.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );
    let connected = run(&["connect", "obs"]);
    let stderr = String::from_utf8_lossy(&connected.stderr);
    assert_eq!(connected.status.code(), Some(0), "{stderr}");
    assert!(stderr.contains("verified client"), "{stderr}");
    assert!(
        !stderr.contains("deadline"),
        "no managed notice for existing access: {stderr}"
    );
    let argv = std::fs::read(&recorded).unwrap();
    assert_eq!(argv, b"obs\0", "M02's launch: `ssh <alias>`, nothing added");
}
