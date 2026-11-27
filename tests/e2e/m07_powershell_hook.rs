//! M07 U8a and A27: load the shipped integration in a real PowerShell host. The
//! serving cases use the runtime's real control and signing endpoints, with a
//! per-run CA held only in memory. No SSH client, server or account store is used.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Duration;

use heimdall_app::ports::{
    AdapterDescriptor, InteractionRequirement, IssuanceRef, IssuerError, IssuerPort,
    IssuerStatusSnapshot, LockContinuity, PrepareOutcome,
};
use heimdall_contract::Timestamp;
use heimdall_contract::event::{EventFilter, EventType};
use heimdall_contract::ids::{
    AccountName, DestinationId, DeviceId, EnrollmentId, IdentityId, OperationId, PolicyId,
    ProfileId, WorkId,
};
use heimdall_contract::issuer::{CaState, IssuerState, IssuerStatus, StoreKind};
use heimdall_contract::managed::{
    ConnectionPolicy, IssuerIsolation, LockBehavior, PreferredMechanism,
};
use heimdall_contract::request::{
    DestinationScopeEnforcement, Enforcement, ExistingConnectionsPolicy, NewAuthenticationExpiry,
    RefreshDependency, RevocationStatus, WorkloadIsolation,
};
use heimdall_contract::trust::{ActivationEventKind, ActivationEventPayload};
use heimdall_credential::cert::{CertificateProfile, SecretCaKey, build_and_sign};
use heimdall_credential::table::SignerTable;
use heimdall_domain::binding::BindingState;
use heimdall_domain::catalog::{
    DestinationDefinition, DestinationRecord, IdentityRecord, IdentitySource, InteractionProfile,
};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentEvidence, EnrollmentForm, EnrollmentRecord,
    EnrollmentState, ExistingAccessRecord, NoProxy, PairPreference, ProjectionStatus,
    RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::environment::{EnvironmentKind, EnvironmentPermissions, EnvironmentRecord};
use heimdall_domain::evidence::EnforcementEvidence;
use heimdall_domain::managed::SlotState;
use heimdall_domain::operation::AdapterIdentity;
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Capability, Scope};
use heimdall_domain::time::SyncStatus;
use heimdall_runtime::config::Config;
use heimdall_runtime::instance::{INSTANCE_FILE, InstanceInfo};
use heimdall_runtime::paths::Paths;
use heimdall_runtime::service::{ManagedOptions, Service, ServiceOptions, SessionLockWiring};
use heimdall_store::{IssuerRecord, Store};
use heimdall_testkit::{
    FakeCredentialAdapter, FakeStep, ScriptedTimeSync, assert_no_canary, home::find_program,
    session_lock::FakeSessionLockSource,
};
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio::process::Command;
use tokio::time::{Instant, sleep, timeout};
use tokio_util::sync::CancellationToken;

const PROMPT: &str = " fixture prompt > ";
const LOCATION: &str = if cfg!(windows) {
    "work $([1]) ' [u8a]"
} else {
    "work $([1]) '\" [u8a]"
};
const LOAD: &str = r#"
$ErrorActionPreference = 'Stop'
function global:prompt { ' fixture prompt > ' }
Invoke-Expression ((& heimdall shell init powershell) -join "`n")
if ($LASTEXITCODE -ne 0) { throw 'shell init failed' }
'loaded'
"#;
const RENDER: &str = r#"
Set-Location -LiteralPath $env:FIXTURE_LOCATION
$global:LASTEXITCODE = 42
prompt
if ($LASTEXITCODE -ne 42) { throw 'hook changed the last exit code' }
'rendered'
"#;
const AFTER_ACTIVATION: &str = r#"
if ($global:__heimdall_state -cne 'active' -or [long]$global:__heimdall_due -le 0) {
    throw 'hook did not retain its active state and recheck deadline'
}
[void][Console]::ReadLine()
$global:__heimdall_seq = '1'
$global:__heimdall_due = '1'
prompt
if ($global:__heimdall_state -cne 'paused') { throw 'hook did not recheck when due' }
$global:__heimdall_due = '1'
prompt
'rechecked'
"#;
const PAUSED: &str = "heimdall: access here is paused, stopped or past its cutoff; nothing was activated. To resume: heimdall access resume";
const HOST_TIMEOUT: Duration = Duration::from_secs(30);

async fn for_each_host<F, Fut>(mut test: F)
where
    F: FnMut(PathBuf) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let legacy = if cfg!(windows) {
        std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .map(|root| root.join("System32/WindowsPowerShell/v1.0/powershell.exe"))
            .filter(|path| path.is_file())
    } else {
        None
    };
    let pwsh = find_program("pwsh").or_else(|| {
        let path = PathBuf::from(std::env::var_os("ProgramFiles")?).join("PowerShell/7/pwsh.exe");
        (cfg!(windows) && path.is_file()).then_some(path)
    });
    let thread = std::thread::current();
    let case = thread.name().unwrap_or("PowerShell hook");
    let mut failed = Vec::new();
    for (edition, host) in [("Windows PowerShell 5.1", legacy), ("PowerShell 7", pwsh)] {
        let outcome = match host {
            Some(ref host) if tokio::spawn(test(host.clone())).await.is_ok() => "passed",
            Some(_) => {
                failed.push(edition);
                "failed"
            }
            None => "absent",
        };
        eprintln!("{case}: {edition}: {outcome}");
    }
    assert!(failed.is_empty(), "failed PowerShell editions: {failed:?}");
}

struct Fixture {
    _scratch: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
    paths: Paths,
    /// The binary `shell init` runs from (`$env:FIXTURE_HEIMDALL`) instead of the one
    /// `PATH` finds; the hook embeds that path (finding S4-02).
    init: Option<PathBuf>,
}

impl Fixture {
    fn new() -> Self {
        // Unix signing sockets need a short absolute path.
        let scratch = if cfg!(unix) {
            tempfile::Builder::new().prefix("hm-ps-").tempdir_in("/tmp")
        } else {
            tempfile::Builder::new().prefix("hm-ps-").tempdir()
        }
        .unwrap();
        let root = scratch.path().to_path_buf();
        let home = root.join("hm");
        for dir in [
            "account/appdata",
            "account/localappdata",
            "ssh/etc-ssh",
            "programdata",
            "temp",
            LOCATION,
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        Self {
            _scratch: scratch,
            root,
            paths: Paths::under(&home),
            home,
            init: None,
        }
    }

    /// A second name for the binary under test, `<root>/<dir>/heimdall` (a hard link, else a
    /// copy), which loads the hook from then on.
    fn install(&mut self, dir: &str) -> PathBuf {
        let dir = self.root.join(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let to = dir.join(format!("heimdall{}", std::env::consts::EXE_SUFFIX));
        let bin = heimdall_bin();
        if std::fs::hard_link(&bin, &to).is_err() {
            std::fs::copy(&bin, &to).unwrap();
        }
        self.init = Some(to.clone());
        to
    }

    /// A decoy `heimdall` in the hostile location, as a checkout would carry: it records
    /// that it ran in [`Fixture::decoy_marker`] and answers as if access were active.
    fn plant_decoy(&self) {
        let marker = self.decoy_marker();
        let marker = marker.to_str().unwrap();
        let dir = self.root.join(LOCATION);
        if cfg!(windows) {
            assert!(!marker.contains(['"', '%', '^', '&']));
            for name in ["heimdall.cmd", "heimdall.bat"] {
                std::fs::write(
                    dir.join(name),
                    format!("@echo off\r\necho ran> \"{marker}\"\r\necho active 7 60\r\n"),
                )
                .unwrap();
            }
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                assert!(!marker.contains('\''));
                let decoy = dir.join("heimdall");
                std::fs::write(
                    &decoy,
                    format!("#!/bin/sh\n: > '{marker}'\nprintf 'active 7 60\\n'\n"),
                )
                .unwrap();
                std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }

    fn decoy_marker(&self) -> PathBuf {
        self.root.join("decoy-ran")
    }

    fn command(&self, host: &Path, body: &str) -> Command {
        let [mgmt, iroh] = self.unused_fixture_stores();
        let script = self.root.join("fixture.ps1");
        let load = if self.init.is_some() {
            LOAD.replacen(
                "& heimdall shell init",
                "& $env:FIXTURE_HEIMDALL shell init",
                1,
            )
        } else {
            LOAD.to_owned()
        };
        std::fs::write(&script, format!("{load}{body}")).unwrap();
        let bin = heimdall_bin();
        let mut path = vec![bin.parent().unwrap().to_owned()];
        let mut cmd = Command::new(host);
        cmd.env_clear()
            .env("HEIMDALL_HOME", &self.home)
            .env("HOME", self.root.join("account"))
            .env("HEIMDALL_TEST_SSH_HOME", self.root.join("ssh"))
            .env("HEIMDALL_TEST_SECRET_STORE", "scratch")
            .env(
                "HEIMDALL_TEST_MGMT_STORE",
                format!("fixture-file:{}", mgmt.to_str().unwrap()),
            )
            .env("HEIMDALL_TEST_IROH_KEY_STORE", iroh)
            .env("FIXTURE_LOCATION", self.root.join(LOCATION))
            .env("PSModulePath", host.parent().unwrap().join("Modules"))
            .env("TEMP", self.root.join("temp"))
            .env("TMP", self.root.join("temp"))
            .env("TMPDIR", self.root.join("temp"))
            .env("XDG_CACHE_HOME", self.root.join("account"))
            .env("XDG_CONFIG_HOME", self.root.join("account"))
            .env("XDG_DATA_HOME", self.root.join("account"))
            .env("POWERSHELL_TELEMETRY_OPTOUT", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .current_dir(&self.root)
            .args(["-NoLogo", "-NoProfile", "-NonInteractive"])
            .kill_on_drop(true);
        if cfg!(windows) {
            let windows = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
            let system = windows.join("System32");
            path.extend([
                system.clone(),
                system.join("WindowsPowerShell/v1.0"),
                windows.clone(),
            ]);
            for name in [
                "ProgramFiles",
                "ProgramFiles(x86)",
                "CommonProgramFiles",
                "CommonProgramFiles(x86)",
            ] {
                if let Some(directory) =
                    std::env::var_os(name).filter(|v| Path::new(v).is_absolute())
                {
                    cmd.env(name, directory);
                }
            }
            cmd.env("SystemRoot", &windows)
                .env("windir", &windows)
                .env("ComSpec", system.join("cmd.exe"))
                .env("PATHEXT", ".COM;.EXE;.BAT;.CMD")
                .args(["-ExecutionPolicy", "Bypass"])
                .env("USERPROFILE", self.root.join("account"))
                .env("ProgramData", self.root.join("programdata"))
                .env("ALLUSERSPROFILE", self.root.join("programdata"))
                .env("APPDATA", self.root.join("account/appdata"))
                .env("LOCALAPPDATA", self.root.join("account/localappdata"));
        } else {
            path.extend(["/usr/bin", "/bin", "/usr/sbin", "/sbin"].map(PathBuf::from));
        }
        if let Some(init) = &self.init {
            cmd.env("FIXTURE_HEIMDALL", init);
        }
        cmd.env("PATH", std::env::join_paths(path).unwrap())
            .arg("-File")
            .arg(script);
        cmd
    }

    fn unused_fixture_stores(&self) -> [PathBuf; 2] {
        assert!(self.root.is_absolute());
        let stores = [
            self.root.join("mgmt-store"),
            self.root.join("iroh-key-store"),
        ];
        for store in &stores {
            assert!(
                store
                    .symlink_metadata()
                    .is_err_and(|err| err.kind() == std::io::ErrorKind::NotFound),
                "unexpected fixture store"
            );
        }
        stores
    }

    async fn output(&self, host: &Path, body: &str) -> Output {
        let stdout = tempfile::NamedTempFile::new_in(&self.root).unwrap();
        let stderr = tempfile::NamedTempFile::new_in(&self.root).unwrap();
        let mut child = self
            .command(host, body)
            .stdin(Stdio::null())
            .stdout(stdout.reopen().unwrap())
            .stderr(stderr.reopen().unwrap())
            .spawn()
            .unwrap();
        let read = || {
            (
                std::fs::read(stdout.path()).unwrap(),
                std::fs::read(stderr.path()).unwrap(),
            )
        };
        let status = timeout(HOST_TIMEOUT, child.wait())
            .await
            .unwrap_or_else(|_| {
                let (stdout, stderr) = read();
                panic!(
                    "PowerShell did not exit\n{}",
                    streams(&self.root, &stdout, &stderr)
                );
            })
            .unwrap();
        self.unused_fixture_stores();
        let (stdout, stderr) = read();
        Output {
            status,
            stdout,
            stderr,
        }
    }

    async fn run(&self, host: &Path, body: &str, stdout: &[&str]) {
        let out = self.output(host, body).await;
        assert_output(&self.root, &out, stdout, &[]);
    }
}

/// The binary under test. A native run copies it elsewhere and names it
/// (`HEIMDALL_E2E_BIN`).
fn heimdall_bin() -> PathBuf {
    std::env::var("HEIMDALL_E2E_BIN")
        .ok()
        .filter(|s| !s.is_empty())
        .map_or_else(
            || PathBuf::from(env!("CARGO_BIN_EXE_heimdall")),
            PathBuf::from,
        )
}

/// Put `.` and then the hostile location first on `PATH`, ahead of the installed client
/// (finding S4-02): a hook that looked `heimdall` up would find the decoy.
const HOSTILE_PATH: &str = r#"
$env:PATH = '.' + [IO.Path]::PathSeparator + $env:FIXTURE_LOCATION + [IO.Path]::PathSeparator + $env:PATH
"#;

fn excerpt(bytes: &[u8], root: &Path) -> String {
    let mut names: Vec<_> = ["USER", "USERNAME", "LOGNAME", "HOSTNAME", "COMPUTERNAME"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .collect();
    names.sort_unstable_by_key(|name| std::cmp::Reverse(name.len()));
    redact_diagnostic(bytes, root, names.iter().map(String::as_str))
}

fn redact_diagnostic<'a>(
    bytes: &[u8],
    root: &Path,
    names: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut text = String::from_utf8_lossy(bytes).into_owned();
    heimdall_testkit::assert_no_canary(&text);
    let root = root.to_string_lossy();
    for path in [
        root.to_string(),
        root.replace('\\', "/"),
        root.replace('\\', "\\\\"),
    ] {
        redact_value(&mut text, &path, "<scratch>");
    }
    // The shared excerpt sanitizer handles exact-case home paths. Also recognize
    // Windows home segments in mixed case and in JSON diagnostics.
    for marker in [r"\\users\\", r"\users\", "/users/"] {
        for (at, _) in text.to_ascii_lowercase().rmatch_indices(marker) {
            let start = at + marker.len();
            let account = &text[start..];
            let len = account
                .find(['/', '\\', '\'', '"', '\r', '\n'])
                .unwrap_or(account.len());
            if len != 0 {
                text.replace_range(start..start + len, "~");
            }
        }
    }
    for name in names {
        redact_value(&mut text, name, "<redacted>");
    }
    heimdall_enroll::remote::redact_excerpt(text.as_bytes(), 4096)
}

fn redact_value(text: &mut String, value: &str, replacement: &str) {
    if value.is_empty() {
        return;
    }
    let mut ranges = Vec::new();
    let mut end = 0;
    for (start, _) in text.char_indices() {
        if start < end {
            continue;
        }
        let mut rest = text[start..].chars();
        if value.chars().all(|expected| {
            rest.next()
                .is_some_and(|actual| actual.to_uppercase().eq(expected.to_uppercase()))
        }) {
            end = text.len() - rest.as_str().len();
            ranges.push(start..end);
        }
    }
    for range in ranges.into_iter().rev() {
        text.replace_range(range, replacement);
    }
}

#[test]
fn diagnostic_redacts_mixed_case_windows_identifiers() {
    let stderr = br#"Failed: C:\uSeRs\ExampleUser\ScRaTcH\raw
{"path":"c:\\USerS\\EXAMPLEUSER\\sCrAtCh\\escaped"}
Path: c:/users/exampleuser/SCRATCH/forward
Other: c:\uSeRs\OtherFixture\file c:\\uSeRs\\OtherFixture\\file c:/uSeRs/OtherFixture/file
Account: eXaMpLeUsEr; Machine: example-pc
"#;
    let redacted = redact_diagnostic(
        stderr,
        Path::new(r"C:\Users\ExampleUser\scratch"),
        ["ExampleUser", "EXAMPLE-PC"],
    );
    assert_eq!(redacted.matches("<scratch>").count(), 3, "{redacted}");
    assert!(
        redacted.contains("Account: <redacted>; Machine: <redacted>"),
        "{redacted}"
    );
    for value in ["exampleuser", "example-pc", "otherfixture"] {
        assert!(!redacted.to_ascii_lowercase().contains(value), "{redacted}");
    }
}

fn streams(root: &Path, stdout: &[u8], stderr: &[u8]) -> String {
    format!(
        "stdout tail: {:?}\nstderr tail: {:?}",
        excerpt(stdout, root),
        excerpt(stderr, root)
    )
}

fn assert_output(root: &Path, out: &Output, expected_stdout: &[&str], expected_stderr: &[&str]) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_no_canary(&stdout);
    assert_no_canary(&stderr);
    assert!(
        out.status.success()
            && stdout.lines().eq(expected_stdout.iter().copied())
            && stderr.lines().eq(expected_stderr.iter().copied()),
        "PowerShell exit: {}; expected stdout {expected_stdout:?}, stderr {expected_stderr:?}\n{}",
        out.status,
        streams(root, &out.stdout, &out.stderr)
    );
}

#[tokio::test]
async fn powershell_hook_writes_nothing_to_stdout() {
    for_each_host(|host| async move {
        let fixture = Fixture::new();
        fixture
            .run(&host, RENDER, &["loaded", PROMPT, "rendered"])
            .await;
        assert!(!fixture.home.exists(), "the hook started no runtime");
    })
    .await;
}

#[cfg(windows)]
#[tokio::test]
async fn powershell_writable_environment_is_in_scratch() {
    for_each_host(|host| async move {
        let fixture = Fixture::new();
        let out = fixture
            .output(
                &host,
                r#"
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
foreach ($name in 'ProgramData', 'ALLUSERSPROFILE', 'TEMP', 'TMP', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA') {
    [Environment]::GetEnvironmentVariable($name)
}
"#,
            )
            .await;
        let paths = [
            "programdata",
            "programdata",
            "temp",
            "temp",
            "account",
            "account/appdata",
            "account/localappdata",
        ];
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut lines = stdout.lines();
        assert!(
            out.status.success()
                && out.stderr.is_empty()
                && lines.next() == Some("loaded")
                && lines.map(|line| Path::new(line).canonicalize().ok()).eq(
                    paths.map(|dir| Some(fixture.root.join(dir).canonicalize().unwrap()))
                ),
            "PowerShell did not inherit its scratch writable directories\n{}",
            streams(&fixture.root, &out.stdout, &out.stderr)
        );
    })
    .await;
}

/// ⟨S4-02⟩ A stale hook: the heimdall that printed it is removed before the prompt. The
/// prompt renders, the error history is untouched, nothing is started, and the decoy that a
/// `PATH` lookup would find in the hostile location never runs.
#[tokio::test]
async fn powershell_hook_missing_executable_leaves_the_error_history_alone() {
    let body = format!(
        "Remove-Item -LiteralPath $env:FIXTURE_HEIMDALL\n{HOSTILE_PATH}\n$before = $Error.Count\n{RENDER}\nif ($Error.Count -ne $before) {{ throw 'hook changed the error history' }}\nif ($global:__heimdall_state -cne 'none') {{ throw 'hook accepted an answer' }}"
    );
    for_each_host(|host| {
        let body = body.clone();
        async move {
            let mut fixture = Fixture::new();
            let installed = fixture.install("gone");
            fixture.plant_decoy();
            fixture
                .run(&host, &body, &["loaded", PROMPT, "rendered"])
                .await;
            assert!(!installed.exists());
            assert!(!fixture.decoy_marker().exists(), "the decoy ran");
            assert!(!fixture.home.exists());
        }
    })
    .await;
}

/// Replace the binary the hook embeds (`$env:FIXTURE_HEIMDALL`) with the stub beside it
/// (`<binary>.stub`), so the hook starts the stub by its embedded path.
#[cfg(unix)]
const REPLACE_WITH_STUB: &str = "Move-Item -LiteralPath ($env:FIXTURE_HEIMDALL + '.stub') -Destination $env:FIXTURE_HEIMDALL -Force";

#[cfg(unix)]
#[tokio::test]
async fn powershell_hook_ignores_start_failures_and_failed_answers() {
    use std::os::unix::fs::PermissionsExt as _;

    for_each_host(|host| async move {
        for (start_fails, stub) in [
            (true, None),
            (false, Some("#!/bin/sh\n: > ran\nprintf 'active 1 60\\n'\nexit 1\n")),
        ] {
            let mut fixture = Fixture::new();
            // The hook embeds the installed path; the stub then takes that file's place.
            let path = fixture.install("stub").with_extension("stub");
            let missing_interpreter = format!("#!{}\n", fixture.root.join("missing").display());
            std::fs::write(&path, stub.unwrap_or(&missing_interpreter)).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            let body = format!(
                r#"
{REPLACE_WITH_STUB}
try {{ throw 'older error' }} catch {{}}
try {{ throw 'newer error' }} catch {{}}
$before = $Error.ToArray()
{RENDER}
if ($Error.Count -ne $before.Length) {{ throw 'hook changed the error count' }}
for ($i = 0; $i -lt $before.Length; $i++) {{
    if (-not [object]::ReferenceEquals($Error[$i], $before[$i])) {{ throw 'hook changed the error history' }}
}}
if ($global:__heimdall_state -cne 'none' -or $global:__heimdall_seq -cne '0' -or $global:__heimdall_due -cne '0') {{
    throw 'hook accepted a failed answer'
}}
"#
            );
            fixture.run(&host, &body, &["loaded", PROMPT, "rendered"]).await;
            assert_eq!(fixture.root.join("ran").exists(), !start_fails);
            assert!(!path.exists(), "the stub replaced the installed binary");
        }
    })
    .await;
}

// Unix shell stubs let us exercise both timeout paths without compiling an executable.
#[cfg(unix)]
#[tokio::test]
async fn powershell_hook_bounds_child_exit_and_inherited_stdout() {
    use std::os::unix::fs::PermissionsExt;

    let timed_render = format!("{REPLACE_WITH_STUB}{TIMED_RENDER}");
    const TIMED_RENDER: &str = r#"
$global:LASTEXITCODE = 42
$timer = [Diagnostics.Stopwatch]::StartNew()
prompt
if ($timer.ElapsedMilliseconds -gt 2200) { throw 'hook exceeded its deadline' }
if ($LASTEXITCODE -ne 42) { throw 'hook changed the last exit code' }
if ($global:__heimdall_state -cne 'none') { throw 'hook consumed an incomplete answer' }
$childId = [int](Get-Content -LiteralPath child.pid)
$child = Get-Process -Id $childId -ErrorAction Ignore
if ($null -ne $child -and -not $child.WaitForExit(250)) { throw 'hook left its child running' }
'rendered'
"#;
    for_each_host(|host| {
        let timed_render = timed_render.clone();
        async move {
        for (stub, holds_stdout) in [
            ("exec /bin/sleep 4", false),
            (
                "(/bin/sleep 4; : > holder.done) </dev/null 2>/dev/null &\nprintf 'active 1 60\\n'",
                true,
            ),
        ] {
            let mut fixture = Fixture::new();
            let path = fixture.install("stub").with_extension("stub");
            std::fs::write(
                &path,
                format!("#!/bin/sh\nprintf '%s\\n' \"$$\" > child.pid\n{stub}\n"),
            )
            .unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
            // Observe the short-lived holder before removing the fixture, even on a failed prompt assertion.
            let out = fixture.output(&host, &format!("\n{timed_render}")).await;
            if holds_stdout {
                timeout(Duration::from_secs(5), async {
                    while !fixture.root.join("holder.done").is_file() {
                        sleep(Duration::from_millis(25)).await;
                    }
                })
                .await
                .expect("the fixture stdout holder exited");
            }
            assert_output(&fixture.root, &out, &["loaded", PROMPT, "rendered"], &[]);
        }
        }
    })
    .await;
}

#[tokio::test]
async fn powershell_hook_startup_with_an_unreachable_runtime() {
    for_each_host(|host| async move {
        let fixture = Fixture::new();
        fixture.paths.ensure().unwrap();
        let token = format!("hmtest-{}", heimdall_testkit::agent::random_hex(16));
        let endpoints =
            heimdall_ipc::EndpointPaths::for_runtime(&fixture.paths.runtime_dir, &token);
        let info = InstanceInfo {
            pid: std::process::id(),
            started_at: InstanceInfo::current_started_at().unwrap(),
            version: "0.0.0".into(),
            control_endpoint: endpoints.control.to_str().unwrap().into(),
            signing_endpoint: endpoints.signing.to_str().unwrap().into(),
        };
        let runtime_dir = &fixture.paths.runtime_dir;
        info.write(runtime_dir).unwrap();
        fixture
            .run(&host, RENDER, &["loaded", PROMPT, "rendered"])
            .await;
        assert_eq!(InstanceInfo::read_file(runtime_dir).unwrap(), Some(info));
        let state_dir = &fixture.paths.state_dir;
        let db = heimdall_store::layout::db_path(state_dir).unwrap();
        assert!(!db.exists());
        // No store generation was published or staged either (ruled 2026-11-25).
        assert_eq!(
            heimdall_store::layout::pointed_generation(state_dir).unwrap(),
            None
        );
        let generations =
            state_dir.join(heimdall_store::layout::stategen::generations::GENERATIONS);
        assert!(
            std::fs::read_dir(&generations).map_or(true, |mut d| d.next().is_none()),
            "the state directory holds a generation"
        );
    })
    .await;
}

// Stand in only for the issuer child. Sign the production driver's reservation with
// the ephemeral CA and the registered subject. No CA secret is put on disk.
struct MemoryIssuer {
    ca: SecretCaKey,
    store: Arc<Store>,
    table: SignerTable,
}

#[async_trait::async_trait]
impl IssuerPort for MemoryIssuer {
    fn status(&self) -> IssuerStatusSnapshot {
        IssuerStatusSnapshot {
            status: IssuerStatus {
                state: IssuerState::Ready,
                reason: None,
                cas: Vec::new(),
                orphan_store_items: Vec::new(),
                issuer_isolation: IssuerIsolation::SameUserProcess,
                bundle_stale: false,
            },
        }
    }

    async fn sign(&self, reservation: IssuanceRef, _: &str) -> Result<String, IssuerError> {
        let refused =
            || IssuerError::Protocol("test issuance could not sign the reservation".into());
        let entry = self
            .store
            .transaction(|tx| tx.issuance_entry(&reservation.id))
            .map_err(|_| refused())?
            .ok_or_else(refused)?;
        let key = self
            .table
            .public_key(&entry.grant)
            .ok_or_else(refused)?
            .public_key()
            .map_err(|_| refused())?;
        build_and_sign(
            &CertificateProfile::from_bounds(&entry.bounds),
            &key,
            &self.ca,
        )
        .map_err(|_| refused())?
        .to_openssh()
        .map_err(|_| refused())
    }

    async fn unload(&self, _: &heimdall_contract::ids::CaFingerprint) -> Result<(), IssuerError> {
        Ok(())
    }
}

// Give the context hook an observed destination independent of the managed default.
// Its fixture adapter does not need a projected SSH configuration or a live agent.
fn context_adapter() -> Arc<FakeCredentialAdapter> {
    let enforcement = EnforcementEvidence {
        report: Enforcement {
            destination_scope: DestinationScopeEnforcement::ClientRouting,
            new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
            workload_isolation: WorkloadIsolation::SharedOsUser,
            existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
            revocation: RevocationStatus::LocalApplied,
            identity_selection: None,
            new_signing_expiry: None,
            owned_multiplexing: None,
            remote_processes: None,
            unmanaged_connections: None,
            issuer_isolation: None,
            ordinary_aliases: None,
            owner_functions: None,
        },
        evidence: Vec::new(),
    };
    let end = Timestamp::now()
        .checked_add(Duration::from_secs(7200))
        .unwrap();
    FakeCredentialAdapter::new(
        AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "hook-fixture".into(),
            },
            capabilities: [Capability::SshAuthentication].into_iter().collect(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: enforcement.clone(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false,
        },
        vec![FakeStep::Prepare(PrepareOutcome {
            usable_until: end,
            offline_until: end,
            refresh_dependency: RefreshDependency::None,
            enforcement,
            credential_ref: "fixture-context".into(),
            availability: Default::default(),
            provider: None,
            integration: Default::default(),
            managed: None,
        })],
    )
}

fn seed(service: &Service, ca: &SecretCaKey) -> (AccessPair, PolicyId) {
    let environment = service.environment();
    let pair = AccessPair {
        destination: DestinationId::parse("hook-fixture").unwrap(),
        account: AccountName::parse("fixture").unwrap(),
    };
    let policy = PolicyId::parse("hook-policy").unwrap();
    let profile = ProfileId::parse("hook-profile").unwrap();
    let now = Timestamp::now();
    let scope = Scope {
        pairs: [pair.clone()].into_iter().collect(),
        capabilities: [Capability::SshAuthentication].into_iter().collect(),
    };
    let identity = IdentityId::from_random_bytes([12; 16]);
    let enrollment = EnrollmentId::from_random_bytes([13; 16]);
    let fingerprint = ca.fingerprint().unwrap();
    let public = ca.public_openssh().unwrap();
    service
        .store()
        .transaction(|tx| {
            tx.upsert_environment(&EnvironmentRecord {
                id: environment.clone(),
                device: DeviceId::from_random_bytes([11; 16]),
                kind: EnvironmentKind::NativeSession,
                label: None,
                permissions: EnvironmentPermissions {
                    automatic_activation: true,
                    managed_signing: true,
                    issuer_access: true,
                },
            })?;
            tx.insert_issuer(&IssuerRecord {
                ca_fingerprint: fingerprint.clone(),
                public_key: public.clone(),
                state: CaState::Active,
                store_kind: StoreKind::LinuxSecretService,
                backup_sha256: "ab".repeat(32),
                backup_created_at: now,
                restored_without_log: false,
                created_at: now,
                retired_at: None,
            })?;
            tx.upsert_identity(&IdentityRecord {
                id: identity.clone(),
                revision: 1,
                source: IdentitySource::PublicKeyFile {
                    path: "fixture.pub".into(),
                },
                public_key: public.clone(),
                fingerprint: fingerprint.to_string(),
                interaction: InteractionProfile {
                    interaction: heimdall_contract::provider::InteractionKind::Unknown,
                    basis: heimdall_contract::provider::EvidenceBasis::Inferred,
                },
                label: None,
                adopted_at: now,
                updated_at: now,
            })?;
            tx.upsert_destination(&DestinationRecord {
                id: pair.destination.clone(),
                alias: pair.destination.to_string(),
                revision: 1,
                definition: DestinationDefinition::Managed {
                    hostname: "hook-fixture.invalid".into(),
                    port: None,
                    account: pair.account.clone(),
                    identity: identity.clone(),
                    jump: None,
                },
                label: None,
                updated_at: now,
            })?;
            tx.seed_enrollment(&EnrollmentRecord {
                marker: marker_for(&enrollment),
                id: enrollment,
                destination: pair.destination.clone(),
                account: pair.account.clone(),
                ca_fingerprint: fingerprint.clone(),
                form: EnrollmentForm::Account,
                registry: RegistryRef {
                    path_display: "fixture/authorized_keys".into(),
                    resolved_by: RegistryResolvedBy::RemoteHome,
                },
                registry_canonical: RegistryCanonical {
                    path: None,
                    resolved_by: RegistryResolvedBy::RemoteHome,
                },
                line_sha256: "cd".repeat(32),
                target: ApprovedTarget {
                    hostname: "hook-fixture.invalid".into(),
                    port: 22,
                    user: pair.account.clone(),
                    proxy: NoProxy::None,
                    host_key: ApprovedHostKey {
                        algorithm: "ssh-ed25519".into(),
                        key: public.split_whitespace().nth(1).unwrap().into(),
                        fingerprint: fingerprint.to_string(),
                    },
                },
                existing_access: ExistingAccessRecord {
                    identity,
                    endpoint: None,
                    public_key_file: None,
                },
                hold: None,
                removal_origin: None,
                late_write: None,
                state: EnrollmentState::Verified,
                verified_at: Some(now),
                evidence: Some(EnrollmentEvidence {
                    client: "OpenSSH_9.9".into(),
                    server: "OpenSSH_fixture".into(),
                    operation: OperationId::from_random_bytes([14; 16]),
                    verified_at: now,
                    fresh_until: now.checked_add(Duration::from_secs(3600)).unwrap(),
                    clock: None,
                }),
                created_at: now,
                updated_at: now,
            })?;
            tx.set_pair_preference(
                &PairPreference {
                    destination: pair.destination.clone(),
                    account: pair.account.clone(),
                    mechanism: PreferredMechanism::ManagedCertificate,
                    projection: ProjectionStatus::Applied { generation: 1 },
                    issuing_cas: [fingerprint].into_iter().collect(),
                },
                now,
            )?;
            tx.upsert_profile(&ProfileDefinition {
                id: profile.clone(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: policy.clone(),
                    revision: PolicyRevision(1),
                    profile: profile.clone(),
                    workspace: None,
                    scope,
                    environments: [environment.clone()].into_iter().collect(),
                    max_window: Duration::from_secs(3600),
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: ConnectionPolicy::default(),
                    default: true,
                },
                false,
            )?;
            let context_profile = ProfileId::parse("hook-context").unwrap();
            let context = DestinationId::parse("hook-context").unwrap();
            tx.upsert_destination(&DestinationRecord {
                id: context.clone(),
                alias: context.to_string(),
                revision: 1,
                definition: DestinationDefinition::Observed,
                label: None,
                updated_at: now,
            })?;
            let scope = Scope {
                pairs: [AccessPair {
                    destination: context,
                    account: pair.account.clone(),
                }]
                .into_iter()
                .collect(),
                capabilities: [Capability::SshAuthentication].into_iter().collect(),
            };
            tx.upsert_profile(&ProfileDefinition {
                id: context_profile.clone(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("hook-context-policy").unwrap(),
                    revision: PolicyRevision(1),
                    profile: context_profile.clone(),
                    workspace: None,
                    scope,
                    environments: [environment.clone()].into_iter().collect(),
                    max_window: Duration::from_secs(3600),
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: ConnectionPolicy::default(),
                    default: false,
                },
                false,
            )?;
            tx.set_default_profile(environment, &context_profile)
        })
        .unwrap();
    (pair, policy)
}

async fn activation_journey(host: &Path, hostile_state: bool) {
    let mut fixture = Fixture::new();
    // ⟨S4-02⟩ The hook is loaded from a binary whose directory name holds a space, a single
    // quote, a smart quote (PowerShell closes a single-quoted string at U+2019 too) and
    // PowerShell syntax; the hostile location carries a decoy `heimdall`, and `PATH` puts `.`
    // and that location first. The journey's activation shows the embedded path ran; the
    // decoy never does.
    fixture.install("inst ' \u{2019} $([1]) dir");
    fixture.plant_decoy();
    let stop = CancellationToken::new();
    let _cancel_on_unwind = stop.clone().drop_guard();
    let mut options = ServiceOptions::with_clock(
        Arc::new(heimdall_runtime::platform::SystemClock::try_new().unwrap()),
        ScriptedTimeSync::new(SyncStatus::Synchronized),
    );
    options.endpoint_prefix = "hmtest-".into();
    options.adapters.push(context_adapter());
    options.managed = Some(ManagedOptions {
        session_lock: SessionLockWiring::Source(Arc::new(FakeSessionLockSource::default())),
        ..ManagedOptions::default()
    });
    let service = Service::start_with(
        fixture.paths.clone(),
        Config::default(),
        options,
        stop.clone(),
    )
    .await
    .expect("start fixture runtime");
    let ca = SecretCaKey::generate().unwrap();
    let (pair, policy) = seed(&service, &ca);
    let store = service.store().clone();
    let environment = service.environment().clone();
    let table = service.endpoint_registry().unwrap().table().clone();
    let mut wiring = service
        .operations()
        .managed_wiring()
        .unwrap()
        .as_ref()
        .clone();
    wiring.issuer = Some(Arc::new(MemoryIssuer {
        ca,
        store: store.clone(),
        table,
    }));
    wiring.issuer_lifecycle = None;
    service.operations().set_managed_wiring(wiring);
    let server = tokio::spawn(service.run());
    let stats = || store.transaction(|tx| tx.table_counts()).unwrap();

    fixture
        .run(host, "'no prompt'\n", &["loaded", "no prompt"])
        .await;
    assert_eq!(stats().grants, 0, "loading the profile does not activate");
    assert_eq!(
        stats().decisions,
        0,
        "non-interactive startup makes no decision"
    );

    let junk = if hostile_state {
        r#"
$global:__heimdall_seq = '1; throw "junk"'
$global:__heimdall_state = @('active', 'not a state')
$global:__heimdall_due = '9999999999999999999999999'
$global:__heimdall_pwd = $env:FIXTURE_LOCATION
"#
    } else {
        ""
    };
    let body = format!("{junk}{HOSTILE_PATH}{RENDER}{AFTER_ACTIVATION}");
    let stderr_path = fixture.root.join("shell-stderr");
    let mut shell = fixture
        .command(host, &body)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(std::fs::File::create(&stderr_path).unwrap())
        .spawn()
        .unwrap();
    let pid = shell.id().unwrap();
    let mut stdout = BufReader::new(shell.stdout.take().unwrap());
    let mut observed = Vec::new();
    let ready = timeout(HOST_TIMEOUT, async {
        for _ in 0..3 {
            if stdout.read_until(b'\n', &mut observed).await? == 0 {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
    let text = String::from_utf8_lossy(&observed);
    assert_no_canary(&text);
    let diagnostic = || {
        streams(
            &fixture.root,
            &observed,
            &std::fs::read(&stderr_path).unwrap_or_default(),
        )
    };
    assert!(
        matches!(ready, Ok(Ok(()))) && text.lines().eq(["loaded", PROMPT, "rendered"]),
        "PowerShell startup {ready:?}; exit {:?}\n{}",
        shell.try_wait().unwrap(),
        diagnostic()
    );
    let start = heimdall_runtime::platform::process_start_time(pid)
        .unwrap_or_else(|| panic!("PowerShell exited after its prompt\n{}", diagnostic()));
    let work = WorkId::parse(&format!("shell:{pid}.{start}.0")).unwrap();

    // The shell is still alive. Its binding and the default's slot reference are
    // separate. The warm-up can finish in the runtime after the hook returns.
    let env_default = heimdall_app::operations::default_work_id(&environment, 1).unwrap();
    let filter = EventFilter {
        operation_id: None,
        types: vec![EventType::Activation],
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let (holders, defaults, events, slot) = store
            .transaction(|tx| {
                let holders = tx
                    .bindings_for_work(&environment, &work)?
                    .into_iter()
                    .filter(|b| b.state == BindingState::Active)
                    .map(|b| tx.binding_holder(&b.id))
                    .collect::<heimdall_store::Result<Vec<_>>>()?;
                Ok((
                    holders,
                    tx.bindings_for_work(&environment, &env_default)?,
                    tx.events_after(&environment, 0, &filter, 20)?.events,
                    tx.slot(&environment, &pair)?,
                ))
            })
            .unwrap();
        if let ([Some(holder)], [default], [event], SlotState::Held { .. }) = (
            holders.as_slice(),
            defaults.as_slice(),
            events.as_slice(),
            slot,
        ) {
            assert_eq!(holder.pid, pid);
            assert_eq!(holder.started_at, start);
            assert_eq!(default.state, BindingState::Active);
            let payload: ActivationEventPayload =
                serde_json::from_value(event.payload.clone()).unwrap();
            assert_eq!(payload.kind, ActivationEventKind::Activated);
            assert_eq!(payload.policy_id.as_ref(), Some(&policy));
            assert_eq!(payload.workspace_id, None);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "expected shell holder, warmed slot and activation event (holders {}, default bindings {}, activation outcomes {:?})",
            holders.len(),
            defaults.len(),
            events
                .iter()
                .map(|e| (&e.payload["kind"], &e.payload["reason"]))
                .collect::<Vec<_>>()
        );
        sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(stats().decisions, 0);

    store
        .transaction(|tx| {
            let id = PolicyId::parse("hook-context-policy").unwrap();
            let mut context = tx.policy(&id)?.unwrap();
            context.revision = PolicyRevision(context.revision.0 + 1);
            context.pause = PauseState::Paused {
                since: Timestamp::now(),
            };
            tx.upsert_policy(&context, false).map(drop)
        })
        .unwrap();
    drop(shell.stdin.take());
    use tokio::io::AsyncReadExt as _;
    let mut remaining = Vec::new();
    let (status, read) = timeout(HOST_TIMEOUT, async {
        tokio::join!(shell.wait(), stdout.read_to_end(&mut remaining))
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "PowerShell did not exit after stdin closed\n{}",
            diagnostic()
        )
    });
    read.unwrap();
    let out = Output {
        status: status.unwrap(),
        stdout: [observed, remaining].concat(),
        stderr: std::fs::read(stderr_path).unwrap(),
    };
    assert_output(
        &fixture.root,
        &out,
        &["loaded", PROMPT, "rendered", PROMPT, PROMPT, "rechecked"],
        &[PAUSED],
    );
    assert_eq!(stats().decisions, 0);
    stop.cancel();
    timeout(HOST_TIMEOUT, server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!fixture.paths.runtime_dir.join(INSTANCE_FILE).exists());
    assert!(!fixture.decoy_marker().exists(), "the decoy ran");
}

#[tokio::test]
async fn powershell_hook_activates_and_warms_the_default() {
    for_each_host(|host| async move { activation_journey(&host, false).await }).await;
}

#[tokio::test]
async fn powershell_hook_recovers_from_hostile_state() {
    for_each_host(|host| async move { activation_journey(&host, true).await }).await;
}
