//! The run-record side channel (m02-plan U8; ADR-0007 §8 "Side channel").
//!
//! **Invariant: no `launching` record means not launched.** Heimdall execs or spawns
//! only after `launching` was written in full (fd: the whole line; file: written and
//! fsync'd). A failed `launching` write aborts the launch (`meta_unavailable`). No
//! record ever carries `argv`.
//!
//! * **fd protocol** (`--meta-fd`, Unix only): each record is the whole line written
//!   to the adopted descriptor; no fsync (a pipe or socket has none).
//! * **file protocol** (`--meta-file`): the file is created exclusively and each
//!   record is one write followed by fsync.
//!
//! After any failed write the channel writes nothing more: a later record must never
//! be appended to a partial line. A reader then sees the last complete record, which
//! the normative reader (`contract::run_record::classify`) never turns into a launch
//! claim.
//!
//! **Encoding** (ADR-0007 §12.15 item 7, U8 E3). Each record is
//! `serde_json::to_vec(record)` and a `\n`: the tag `type` first, then the fields in
//! declaration order, `None` fields omitted, `consumer_overrides` always present, one
//! line (serde_json escapes every control character). The golden test
//! `encoding_matches_the_committed_examples` holds the bytes to the committed
//! `schemas/examples/run-record.*.json`. A record that cannot be encoded is a write
//! failure, so `launching` then aborts the launch.

use std::fs::File;
use std::io::Write as _;
use std::path::Path;

use heimdall_contract::Code;
use heimdall_contract::ids::{BindingId, OperationId};
use heimdall_contract::request::ConsumerOverride;
use heimdall_contract::run_record::RunRecord;
use heimdall_contract::version::SchemaVersion;

/// Why the side channel cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MetaError {
    /// `--meta-fd` is not open, or not a pipe, socket or regular file
    /// (`USAGE_ERROR` before `ensure`). Descriptors 0, 1 and 2 are refused too:
    /// adopting one would set close-on-exec on the child's own stdio.
    #[error("meta descriptor unusable")]
    BadDescriptor,
    /// `--meta-file` exists (`USAGE_ERROR` before `ensure`).
    #[error("meta file exists")]
    Exists,
    /// A write failed (`meta_unavailable` for `launching`), or `--meta-file` could
    /// not be created for another reason (`USAGE_ERROR` before `ensure`).
    #[error("meta write failed")]
    Write,
}

/// Which protocol the channel speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    /// `--meta-fd`: whole line, no fsync.
    #[cfg(unix)]
    Fd,
    /// `--meta-file`: one write, then fsync.
    File,
}

/// An open side channel.
#[derive(Debug)]
pub struct SideChannel {
    file: File,
    protocol: Protocol,
    operation_id: Option<OperationId>,
    binding_id: Option<BindingId>,
    failed: bool,
}

impl SideChannel {
    /// Adopt `--meta-fd <n>` (Unix only): `F_GETFD`, type check, `FD_CLOEXEC`
    /// (through `heimdall_localenv::sys::adopt_inherited_fd`). Descriptors below 3
    /// are refused before adoption: close-on-exec on stdin, stdout or stderr would
    /// close the child's stdio.
    ///
    /// # Errors
    /// [`MetaError::BadDescriptor`].
    pub fn from_fd(fd: i32) -> Result<SideChannel, MetaError> {
        #[cfg(unix)]
        {
            if fd < 3 {
                return Err(MetaError::BadDescriptor);
            }
            let owned = heimdall_localenv::sys::adopt_inherited_fd(fd)
                .map_err(|_| MetaError::BadDescriptor)?;
            Ok(SideChannel::over_fd(owned))
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
            Err(MetaError::BadDescriptor)
        }
    }

    /// Create `--meta-file <path>` exclusively and owner-only, through
    /// `heimdall_localenv::sys::create_owner_only_exclusive` (ADR-0007 §12.15 item 8,
    /// E4):
    /// * Unix: `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode 0600 (the umask can
    ///   only narrow it). An existing entry, a symbolic link included, is never followed
    ///   or replaced.
    /// * Windows: `CREATE_NEW` with `FILE_FLAG_OPEN_REPARSE_POINT` and a protected DACL
    ///   granting the current user alone; the handle is not inheritable.
    ///
    /// The descriptor is close-on-exec (Unix) and not inheritable (Windows), so the
    /// child never holds it.
    ///
    /// # Errors
    /// [`MetaError::Exists`] when the name exists; [`MetaError::Write`] when the file
    /// cannot be created for another reason.
    pub fn create_exclusive(path: &Path) -> Result<SideChannel, MetaError> {
        match heimdall_localenv::sys::create_owner_only_exclusive(path) {
            Ok(file) => Ok(SideChannel::new(file, Protocol::File)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(MetaError::Exists),
            Err(_) => Err(MetaError::Write),
        }
    }

    /// The operation and binding the `launching` and `prelaunch_failed` records this
    /// crate writes name (`run` knows them after `bind`; `exec_replace` and
    /// `spawn_and_wait` take only the channel).
    #[must_use]
    pub fn with_ids(
        mut self,
        operation_id: Option<OperationId>,
        binding_id: Option<BindingId>,
    ) -> SideChannel {
        self.operation_id = operation_id;
        self.binding_id = binding_id;
        self
    }

    /// Write one record as one NDJSON line (a file write is followed by fsync).
    ///
    /// # Errors
    /// [`MetaError::Write`]: the record cannot be encoded, the write or fsync
    /// failed (for example `EPIPE` after the reader closed), or an earlier write
    /// failed.
    pub fn write(&mut self, record: &RunRecord) -> Result<(), MetaError> {
        if self.failed {
            return Err(MetaError::Write);
        }
        let line = encode_line(record).ok_or(MetaError::Write)?;
        let written = self.file.write_all(&line).and_then(|()| {
            if self.protocol == Protocol::File {
                self.file.sync_all()
            } else {
                Ok(())
            }
        });
        written.map_err(|_| {
            self.failed = true;
            MetaError::Write
        })
    }

    /// `prelaunch_failed` with `code`, `exit_code` and `reason`, naming this channel's
    /// operation and binding: a Heimdall failure before launch (ADR-0006 §6 table; a
    /// pre-launch eligibility refusal is `INTERACTION_REQUIRED`, exit 3).
    ///
    /// # Errors
    /// [`MetaError::Write`].
    pub fn write_prelaunch_failed(
        &mut self,
        code: Code,
        exit_code: i32,
        reason: Option<&str>,
    ) -> Result<(), MetaError> {
        let record = RunRecord::PrelaunchFailed {
            schema_version: SchemaVersion::current(),
            code,
            exit_code,
            reason: reason.map(str::to_owned),
            operation_id: self.operation_id.clone(),
            binding_id: self.binding_id.clone(),
        };
        self.write(&record)
    }

    /// Whether a write on this channel failed (nothing more is written).
    #[must_use]
    pub fn has_failed(&self) -> bool {
        self.failed
    }

    /// Whether this channel speaks the fd protocol.
    #[cfg(unix)]
    pub(crate) fn is_fd(&self) -> bool {
        self.protocol == Protocol::Fd
    }

    /// `launching` for `executable`, naming this channel's operation and binding.
    pub(crate) fn write_launching(
        &mut self,
        executable: &str,
        consumer_overrides: &[ConsumerOverride],
    ) -> Result<(), MetaError> {
        let record = RunRecord::Launching {
            schema_version: SchemaVersion::current(),
            attempt: 1,
            executable: executable.to_owned(),
            operation_id: self.operation_id.clone(),
            binding_id: self.binding_id.clone(),
            pid: std::process::id(),
            consumer_overrides: consumer_overrides.to_vec(),
        };
        self.write(&record)
    }

    /// `prelaunch_failed` with code `LAUNCH_FAILED`.
    pub(crate) fn write_launch_failed(
        &mut self,
        exit_code: i32,
        reason: &str,
    ) -> Result<(), MetaError> {
        self.write_prelaunch_failed(Code::LaunchFailed, exit_code, Some(reason))
    }

    /// Windows: `spawned` with the child's PID.
    #[cfg(windows)]
    pub(crate) fn write_spawned(&mut self, pid: u32) -> Result<(), MetaError> {
        self.write(&RunRecord::Spawned {
            schema_version: SchemaVersion::current(),
            pid,
        })
    }

    /// Windows: `exited` with the child's exact exit code.
    #[cfg(windows)]
    pub(crate) fn write_exited(&mut self, exit_code: u32) -> Result<(), MetaError> {
        self.write(&RunRecord::Exited {
            schema_version: SchemaVersion::current(),
            exit_code: i64::from(exit_code),
        })
    }

    fn new(file: File, protocol: Protocol) -> SideChannel {
        SideChannel {
            file,
            protocol,
            operation_id: None,
            binding_id: None,
            failed: false,
        }
    }

    /// The fd protocol over an adopted descriptor.
    #[cfg(unix)]
    pub(crate) fn over_fd(fd: std::os::fd::OwnedFd) -> SideChannel {
        SideChannel::new(File::from(fd), Protocol::Fd)
    }
}

/// One record as its NDJSON line (`serde_json`, then `\n`), or `None` when it cannot
/// be encoded.
pub(crate) fn encode_line(record: &RunRecord) -> Option<Vec<u8>> {
    let mut line = serde_json::to_vec(record).ok()?;
    line.push(b'\n');
    Some(line)
}

/// Scratch directories for this crate's tests: a fresh, owner-only directory under
/// the system temporary directory, removed (exactly that directory) on drop.
///
/// Also the fork gate (Unix): see [`scratch::fork_gate`].
#[cfg(test)]
pub(crate) mod scratch {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Serializes this test binary's process creation with the tests that assert how a
    /// descriptor closes.
    ///
    /// A child made by `fork` or `posix_spawn` holds a copy of every descriptor its
    /// parent had open at that moment, close-on-exec ones included, until its `exec`
    /// closes them. A test thread that drops a pipe's reader and then expects `EPIPE`
    /// therefore sees the write succeed when another test thread's spawn copied the
    /// reader and has not yet reached `exec` (observed on macOS: about 4 in 100 runs of
    /// this crate's tests, each time with spawns of the exec tests in flight). The
    /// copy dies within a few hundred microseconds, so the flake is intermittent and
    /// the test passes alone.
    ///
    /// The rule: every spawn in these tests goes through [`spawn`], which holds the
    /// gate for the whole call (it returns after the child's `exec`), and a test whose
    /// outcome depends on a descriptor's last holder closing holds [`fork_gate`] from
    /// before it creates the descriptor until it has observed the outcome.
    #[cfg(unix)]
    static FORK_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Hold the fork gate. A poisoned gate (a test panicked holding it) still serves:
    /// it protects no data.
    #[cfg(unix)]
    pub(crate) fn fork_gate() -> std::sync::MutexGuard<'static, ()> {
        FORK_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// `command.spawn()` under the fork gate.
    #[cfg(unix)]
    pub(crate) fn spawn(
        command: &mut std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        let _gate = fork_gate();
        command.spawn()
    }

    /// One scratch directory.
    #[derive(Debug)]
    pub(crate) struct Scratch {
        path: PathBuf,
    }

    impl Scratch {
        /// Create a new, empty directory.
        #[allow(clippy::expect_used)]
        pub(crate) fn new() -> Scratch {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            for _ in 0..64 {
                let n = NEXT.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("hm-u8-{}-{nanos:x}-{n}", std::process::id()));
                if std::fs::create_dir(&path).is_ok() {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt as _;
                        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                            .expect("scratch mode");
                    }
                    return Scratch { path };
                }
            }
            panic!("no scratch directory could be created");
        }

        /// The directory.
        pub(crate) fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::scratch::Scratch;
    use super::*;
    use heimdall_contract::doctor::{ConfigProvenance, GitScope};
    use heimdall_contract::request::{ConsumerKind, OverrideSource};
    use heimdall_contract::run_record::{LaunchClassification, RunPlatform, classify};

    fn op() -> OperationId {
        OperationId::parse("op_00112233445566778899aabbccddeeff").unwrap()
    }

    fn binding() -> BindingId {
        BindingId::parse("binding_0123456789abcdef0123456789abcdef").unwrap()
    }

    fn git_local() -> ConsumerOverride {
        ConsumerOverride {
            consumer: ConsumerKind::Git,
            setting: "core.sshCommand".to_owned(),
            source: OverrideSource::GitScope {
                scope: GitScope::Local,
            },
        }
    }

    /// The committed example without insignificant whitespace.
    fn example(name: &str) -> String {
        // The repository through HM_REPO_ROOT (ADR-0007 §12.32 item 3).
        let path = heimdall_testkit::repo::repo_path("schemas/examples")
            .join(format!("run-record.{name}.json"));
        let text = std::fs::read_to_string(path).unwrap();
        let mut out = String::new();
        let (mut in_string, mut escaped) = (false, false);
        for c in text.chars() {
            if in_string {
                out.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                }
            } else if c == '"' {
                in_string = true;
                out.push(c);
            } else if !c.is_whitespace() {
                out.push(c);
            }
        }
        out.push('\n');
        out
    }

    fn line(record: &RunRecord) -> String {
        String::from_utf8(encode_line(record).unwrap()).unwrap()
    }

    #[test]
    fn encoding_matches_the_committed_examples() {
        let launching = RunRecord::Launching {
            schema_version: SchemaVersion::current(),
            attempt: 1,
            executable: "/usr/bin/git".to_owned(),
            operation_id: Some(op()),
            binding_id: Some(binding()),
            pid: 4242,
            consumer_overrides: vec![git_local()],
        };
        assert_eq!(line(&launching), example("launching"));
        let failed = RunRecord::PrelaunchFailed {
            schema_version: SchemaVersion::current(),
            code: Code::LaunchFailed,
            exit_code: 127,
            reason: Some("not_found".to_owned()),
            operation_id: Some(op()),
            binding_id: Some(binding()),
        };
        assert_eq!(line(&failed), example("prelaunch-failed"));
        let spawned = RunRecord::Spawned {
            schema_version: SchemaVersion::current(),
            pid: 5151,
        };
        assert_eq!(line(&spawned), example("spawned"));
        let exited = RunRecord::Exited {
            schema_version: SchemaVersion::current(),
            exit_code: 3_221_225_786,
        };
        assert_eq!(line(&exited), example("exited"));
    }

    #[test]
    fn optional_fields_are_omitted_and_overrides_always_present() {
        let launching = RunRecord::Launching {
            schema_version: SchemaVersion::current(),
            attempt: 1,
            executable: "/bin/sh".to_owned(),
            operation_id: None,
            binding_id: None,
            pid: 7,
            consumer_overrides: Vec::new(),
        };
        assert_eq!(
            line(&launching),
            "{\"type\":\"launching\",\"schema_version\":\"1\",\"attempt\":1,\
             \"executable\":\"/bin/sh\",\"pid\":7,\"consumer_overrides\":[]}\n"
        );
        let failed = RunRecord::PrelaunchFailed {
            schema_version: SchemaVersion::current(),
            code: Code::InteractionRequired,
            exit_code: 3,
            reason: None,
            operation_id: None,
            binding_id: None,
        };
        assert_eq!(
            line(&failed),
            "{\"type\":\"prelaunch_failed\",\"schema_version\":\"1\",\
             \"code\":\"INTERACTION_REQUIRED\",\"exit_code\":3}\n"
        );
    }

    #[test]
    fn every_override_source_uses_the_tagged_form() {
        let overrides = vec![
            ConsumerOverride {
                consumer: ConsumerKind::Ssh,
                setting: "IdentityAgent".to_owned(),
                source: OverrideSource::SshConfig(ConfigProvenance {
                    path_display: "~/.ssh/config".to_owned(),
                    line: 12,
                }),
            },
            ConsumerOverride {
                consumer: ConsumerKind::SshKeygen,
                setting: "SSH_AUTH_SOCK".to_owned(),
                source: OverrideSource::Environment,
            },
            ConsumerOverride {
                consumer: ConsumerKind::Git,
                setting: "core.sshCommand".to_owned(),
                source: OverrideSource::GitScope {
                    scope: GitScope::Command,
                },
            },
        ];
        let launching = RunRecord::Launching {
            schema_version: SchemaVersion::current(),
            attempt: 1,
            executable: "/bin/sh".to_owned(),
            operation_id: None,
            binding_id: None,
            pid: 7,
            consumer_overrides: overrides,
        };
        assert_eq!(
            line(&launching),
            "{\"type\":\"launching\",\"schema_version\":\"1\",\"attempt\":1,\
             \"executable\":\"/bin/sh\",\"pid\":7,\"consumer_overrides\":[\
             {\"consumer\":\"ssh\",\"setting\":\"IdentityAgent\",\"source\":\
             {\"kind\":\"ssh_config\",\"path_display\":\"~/.ssh/config\",\"line\":12}},\
             {\"consumer\":\"ssh_keygen\",\"setting\":\"SSH_AUTH_SOCK\",\"source\":\
             {\"kind\":\"environment\"}},\
             {\"consumer\":\"git\",\"setting\":\"core.sshCommand\",\"source\":\
             {\"kind\":\"git_scope\",\"scope\":\"command\"}}]}\n"
        );
        // Every Git scope has its wire name inside the tagged source.
        for (scope, wire) in [
            (GitScope::System, "system"),
            (GitScope::Global, "global"),
            (GitScope::Local, "local"),
            (GitScope::Worktree, "worktree"),
            (GitScope::Command, "command"),
        ] {
            let record = RunRecord::Launching {
                schema_version: SchemaVersion::current(),
                attempt: 1,
                executable: "/bin/sh".to_owned(),
                operation_id: None,
                binding_id: None,
                pid: 7,
                consumer_overrides: vec![ConsumerOverride {
                    consumer: ConsumerKind::Git,
                    setting: "core.sshCommand".to_owned(),
                    source: OverrideSource::GitScope { scope },
                }],
            };
            assert!(
                line(&record).contains(&format!("\"scope\":\"{wire}\"")),
                "{wire}"
            );
        }
    }

    #[test]
    fn strings_are_escaped_and_every_record_stays_on_one_line() {
        let launching = RunRecord::Launching {
            schema_version: SchemaVersion::current(),
            attempt: 1,
            executable: "/odd\n\"path\"\r\t\u{1}\u{1f}\u{7f}\u{e9}\u{2028}".to_owned(),
            operation_id: None,
            binding_id: None,
            pid: 1,
            consumer_overrides: Vec::new(),
        };
        let text = line(&launching);
        assert_eq!(text.matches('\n').count(), 1);
        assert!(text.ends_with('\n'));
        assert!(
            text.contains(
                "\"executable\":\"/odd\\n\\\"path\\\"\\r\\t\\u0001\\u001f\u{7f}\u{e9}\u{2028}\""
            ),
            "{text}"
        );
        // The line decodes back to the same record (the reader's side).
        let back: RunRecord = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(back, launching);
    }

    #[test]
    fn meta_file_is_created_exclusively_owner_only_and_records_are_fsynced_lines() {
        let dir = Scratch::new();
        let path = dir.path().join("meta.ndjson");
        let mut channel = SideChannel::create_exclusive(&path)
            .unwrap()
            .with_ids(Some(op()), Some(binding()));
        assert_eq!(channel.protocol, Protocol::File);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777 & !0o600, 0, "mode {mode:o} wider than 0600");
        }
        channel.write_launching("/bin/sh", &[git_local()]).unwrap();
        channel.write_launch_failed(127, "exec_error").unwrap();
        drop(channel);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("{\"type\":\"launching\",\"schema_version\":\"1\""));
        assert!(lines[0].contains(&format!("\"pid\":{}", std::process::id())));
        assert!(lines[0].contains("\"operation_id\":\"op_00112233445566778899aabbccddeeff\""));
        assert!(lines[1].contains("\"code\":\"LAUNCH_FAILED\""));
        assert!(lines[1].contains("\"reason\":\"exec_error\""));
        assert!(lines[1].contains("\"binding_id\":\"binding_0123456789abcdef0123456789abcdef\""));
        assert!(text.ends_with('\n'));
    }

    #[test]
    fn existing_meta_file_is_refused_and_left_untouched() {
        let dir = Scratch::new();
        let path = dir.path().join("meta.ndjson");
        std::fs::write(&path, b"owner bytes").unwrap();
        assert_eq!(
            SideChannel::create_exclusive(&path).unwrap_err(),
            MetaError::Exists
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"owner bytes");
        assert_eq!(
            SideChannel::create_exclusive(&dir.path().join("missing/meta")).unwrap_err(),
            MetaError::Write
        );
    }

    #[cfg(unix)]
    #[test]
    fn meta_file_symlink_is_never_followed() {
        let dir = Scratch::new();
        let target = dir.path().join("target");
        let link = dir.path().join("meta.ndjson");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            SideChannel::create_exclusive(&link).unwrap_err(),
            MetaError::Exists
        );
        assert!(!target.exists(), "the dangling link's target was created");
    }

    #[cfg(unix)]
    #[test]
    fn stdio_descriptors_and_negative_numbers_are_never_adopted() {
        for fd in [-1, 0, 1, 2] {
            assert_eq!(
                SideChannel::from_fd(fd).unwrap_err(),
                MetaError::BadDescriptor
            );
        }
    }

    /// One round of the fd protocol over a fresh pipe: a whole line, then the reader
    /// closes and the next write is an error, not a signal. The caller holds the fork
    /// gate ([`scratch::fork_gate`]): the outcome depends on this test's reader being
    /// the pipe's last holder once it is dropped, and a concurrent spawn would hold a
    /// copy of it until its `exec`.
    #[cfg(unix)]
    fn fd_protocol_round(_gate: &std::sync::MutexGuard<'static, ()>) {
        use std::io::Read as _;
        let (mut reader, writer) = std::io::pipe().unwrap();
        let mut channel =
            SideChannel::over_fd(std::os::fd::OwnedFd::from(writer)).with_ids(Some(op()), None);
        assert!(channel.is_fd());
        channel.write_launching("/usr/bin/ssh", &[]).unwrap();
        let mut first = vec![0_u8; 4096];
        let n = reader.read(&mut first).unwrap();
        let first = String::from_utf8(first[..n].to_vec()).unwrap();
        assert!(first.starts_with("{\"type\":\"launching\""));
        assert!(first.ends_with("\"consumer_overrides\":[]}\n"));
        drop(reader);
        // The reader is gone: EPIPE. Rust ignores SIGPIPE, so this process lives.
        assert_eq!(
            channel.write_launch_failed(127, "exec_error").unwrap_err(),
            MetaError::Write
        );
        // After a failed write nothing more is attempted.
        assert_eq!(
            channel
                .write(&RunRecord::Spawned {
                    schema_version: SchemaVersion::current(),
                    pid: 1
                })
                .unwrap_err(),
            MetaError::Write
        );
    }

    #[cfg(unix)]
    #[test]
    fn fd_protocol_writes_whole_lines_and_epipe_is_an_error_not_a_signal() {
        fd_protocol_round(&scratch::fork_gate());
    }

    /// The fork gate holds: with another thread spawning children in a loop through
    /// the gate, every closed reader is seen as closed. A spawner that bypasses the gate
    /// makes this test fail on its first rounds with the same `Ok(())` where `EPIPE` is
    /// expected (checked by hand when the gate was added).
    #[cfg(unix)]
    #[test]
    fn a_closed_reader_is_never_masked_by_a_concurrent_spawn() {
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let spawned = std::sync::Arc::new(AtomicU32::new(0));
        let spawner = {
            let (stop, spawned) = (stop.clone(), spawned.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let mut child = scratch::spawn(
                        std::process::Command::new("/bin/sh")
                            .args(["-c", ":"])
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null()),
                    )
                    .unwrap();
                    child.wait().unwrap();
                    spawned.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        // Rounds run until the spawner has made progress between them, so the two
        // threads interleave for real (the gate is released between rounds).
        let mut rounds = 0_u32;
        while rounds < 300 || spawned.load(Ordering::Relaxed) < 20 {
            fd_protocol_round(&scratch::fork_gate());
            rounds += 1;
            std::thread::yield_now();
            assert!(rounds < 100_000, "the spawner made no progress");
        }
        stop.store(true, Ordering::Relaxed);
        spawner.join().unwrap();
    }

    #[test]
    fn records_written_by_the_channel_classify_as_the_reader_table_says() {
        let dir = Scratch::new();
        let path = dir.path().join("meta.ndjson");
        let mut channel = SideChannel::create_exclusive(&path)
            .unwrap()
            .with_ids(Some(op()), None);
        channel.write_launching("/bin/true", &[]).unwrap();
        let read = |path: &Path| -> Vec<RunRecord> {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        };
        let records = read(&path);
        assert_eq!(
            records,
            [RunRecord::Launching {
                schema_version: SchemaVersion::current(),
                attempt: 1,
                executable: "/bin/true".to_owned(),
                operation_id: Some(op()),
                binding_id: None,
                pid: std::process::id(),
                consumer_overrides: Vec::new(),
            }]
        );
        assert_eq!(
            classify(&records, RunPlatform::Unix),
            LaunchClassification::Indeterminate
        );
        // A Heimdall failure before launch: `prelaunch_failed` with its own code.
        let other = dir.path().join("refused.ndjson");
        let mut channel = SideChannel::create_exclusive(&other)
            .unwrap()
            .with_ids(Some(op()), Some(binding()));
        channel
            .write_prelaunch_failed(
                Code::InteractionRequired,
                3,
                Some("fallback_identity_interaction"),
            )
            .unwrap();
        assert!(!channel.has_failed());
        let records = read(&other);
        assert_eq!(
            classify(&records, RunPlatform::Unix),
            LaunchClassification::NotLaunched {
                code: Some(Code::InteractionRequired),
                reason: Some("fallback_identity_interaction".to_owned()),
            }
        );
        assert_eq!(
            records,
            [RunRecord::PrelaunchFailed {
                schema_version: SchemaVersion::current(),
                code: Code::InteractionRequired,
                exit_code: 3,
                reason: Some("fallback_identity_interaction".to_owned()),
                operation_id: Some(op()),
                binding_id: Some(binding()),
            }]
        );
    }
}
