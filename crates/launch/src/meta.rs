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
//! **Encoding.** Each record is one JSON object and a `\n`, with exactly the field
//! names, order and string escaping serde gives [`RunRecord`] (tag `type` first, then
//! the fields in declaration order, `None` fields omitted, `consumer_overrides`
//! always present). The encoder is written out here because this crate has no JSON
//! dependency; `encoding_matches_the_committed_examples` holds it to the committed
//! `schemas/examples/run-record.*.json`. A record this build cannot encode (a
//! variant added later) is a write failure, so `launching` then aborts the launch.

use std::fmt::Write as _;
use std::fs::File;
use std::io::Write as _;
use std::path::Path;

use heimdall_contract::Code;
use heimdall_contract::doctor::GitScope;
use heimdall_contract::ids::{BindingId, OperationId};
use heimdall_contract::request::{ConsumerKind, ConsumerOverride, OverrideSource};
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

    /// Create `--meta-file <path>` exclusively (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600, or an
    /// owner-only DACL).
    ///
    /// Unix: `O_CREAT|O_EXCL` with mode 0600 (the umask can only narrow it). With
    /// both flags `open` fails on an existing final component, a symbolic link
    /// included, so it never follows one (POSIX `open`, `[EEXIST]`); `O_NOFOLLOW`
    /// adds nothing there. Windows: `CREATE_NEW` with `FILE_FLAG_OPEN_REPARSE_POINT`,
    /// so a reparse point at the name is the existing entry, never followed. The file
    /// keeps the DACL it inherits from its directory: an explicit owner-only DACL
    /// needs a Win32 security call this crate has no dependency for (escalated in
    /// the M02-W1-U8core report). The descriptor is close-on-exec (Unix) and not
    /// inheritable (Windows), so the child never holds it.
    ///
    /// # Errors
    /// [`MetaError::Exists`] when the name exists; [`MetaError::Write`] when the file
    /// cannot be created for another reason.
    pub fn create_exclusive(path: &Path) -> Result<SideChannel, MetaError> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            /// `FILE_FLAG_OPEN_REPARSE_POINT` (winbase.h).
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        match options.open(path) {
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
        let record = RunRecord::PrelaunchFailed {
            schema_version: SchemaVersion::current(),
            code: Code::LaunchFailed,
            exit_code,
            reason: Some(reason.to_owned()),
            operation_id: self.operation_id.clone(),
            binding_id: self.binding_id.clone(),
        };
        self.write(&record)
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

/// One record as its NDJSON line, or `None` for a variant this build cannot encode.
pub(crate) fn encode_line(record: &RunRecord) -> Option<Vec<u8>> {
    let mut o = Obj::new();
    match record {
        RunRecord::PrelaunchFailed {
            schema_version,
            code,
            exit_code,
            reason,
            operation_id,
            binding_id,
        } => {
            o.str("type", "prelaunch_failed");
            o.str("schema_version", &schema_version.0);
            o.str("code", code.as_str());
            o.num("exit_code", exit_code);
            if let Some(reason) = reason {
                o.str("reason", reason);
            }
            ids(&mut o, operation_id.as_ref(), binding_id.as_ref());
        }
        RunRecord::Launching {
            schema_version,
            attempt,
            executable,
            operation_id,
            binding_id,
            pid,
            consumer_overrides,
        } => {
            o.str("type", "launching");
            o.str("schema_version", &schema_version.0);
            o.num("attempt", attempt);
            o.str("executable", executable);
            ids(&mut o, operation_id.as_ref(), binding_id.as_ref());
            o.num("pid", pid);
            let mut items = Vec::with_capacity(consumer_overrides.len());
            for item in consumer_overrides {
                items.push(encode_override(item)?);
            }
            o.raw("consumer_overrides", &format!("[{}]", items.join(",")));
        }
        RunRecord::Spawned {
            schema_version,
            pid,
        } => {
            o.str("type", "spawned");
            o.str("schema_version", &schema_version.0);
            o.num("pid", pid);
        }
        RunRecord::Exited {
            schema_version,
            exit_code,
        } => {
            o.str("type", "exited");
            o.str("schema_version", &schema_version.0);
            o.num("exit_code", exit_code);
        }
        _ => return None,
    }
    let mut line = o.finish().into_bytes();
    line.push(b'\n');
    Some(line)
}

fn ids(o: &mut Obj, operation_id: Option<&OperationId>, binding_id: Option<&BindingId>) {
    if let Some(id) = operation_id {
        o.str("operation_id", id.as_str());
    }
    if let Some(id) = binding_id {
        o.str("binding_id", id.as_str());
    }
}

/// `ConsumerOverride`; its `source` is tagged by `kind`, a newtype variant's struct
/// fields inlined after the tag (serde's internally tagged form).
fn encode_override(item: &ConsumerOverride) -> Option<String> {
    let consumer = match item.consumer {
        ConsumerKind::Ssh => "ssh",
        ConsumerKind::Scp => "scp",
        ConsumerKind::Sftp => "sftp",
        ConsumerKind::Git => "git",
        ConsumerKind::SshKeygen => "ssh_keygen",
        _ => return None,
    };
    let mut source = Obj::new();
    match &item.source {
        OverrideSource::SshConfig(provenance) => {
            source.str("kind", "ssh_config");
            source.str("path_display", &provenance.path_display);
            source.num("line", &provenance.line);
        }
        OverrideSource::GitScope { scope } => {
            source.str("kind", "git_scope");
            source.str("scope", git_scope(*scope)?);
        }
        OverrideSource::Environment => source.str("kind", "environment"),
        _ => return None,
    }
    let mut o = Obj::new();
    o.str("consumer", consumer);
    o.str("setting", &item.setting);
    o.raw("source", &source.finish());
    Some(o.finish())
}

fn git_scope(scope: GitScope) -> Option<&'static str> {
    Some(match scope {
        GitScope::System => "system",
        GitScope::Global => "global",
        GitScope::Local => "local",
        GitScope::Worktree => "worktree",
        GitScope::Command => "command",
        _ => return None,
    })
}

/// A compact JSON object under construction.
struct Obj {
    out: String,
    first: bool,
}

impl Obj {
    fn new() -> Obj {
        Obj {
            out: String::from("{"),
            first: true,
        }
    }

    fn key(&mut self, key: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        push_json_string(&mut self.out, key);
        self.out.push(':');
    }

    fn str(&mut self, key: &str, value: &str) {
        self.key(key);
        push_json_string(&mut self.out, value);
    }

    fn num(&mut self, key: &str, value: &impl std::fmt::Display) {
        self.key(key);
        let _ = write!(self.out, "{value}");
    }

    fn raw(&mut self, key: &str, json: &str) {
        self.key(key);
        self.out.push_str(json);
    }

    fn finish(mut self) -> String {
        self.out.push('}');
        self.out
    }
}

/// A JSON string with serde_json's escaping: `"` and `\` escaped, the short forms
/// `\b \t \n \f \r`, every other control character below U+0020 as `\u00xx`
/// (lowercase hex), everything else verbatim.
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Scratch directories for this crate's tests: a fresh, owner-only directory under
/// the system temporary directory, removed (exactly that directory) on drop.
#[cfg(test)]
pub(crate) mod scratch {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

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
    use heimdall_contract::doctor::ConfigProvenance;
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
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/examples")
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
        let overrides = [
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
        let encoded: Vec<String> = overrides
            .iter()
            .map(|o| encode_override(o).unwrap())
            .collect();
        assert_eq!(
            encoded,
            [
                "{\"consumer\":\"ssh\",\"setting\":\"IdentityAgent\",\"source\":\
                 {\"kind\":\"ssh_config\",\"path_display\":\"~/.ssh/config\",\"line\":12}}",
                "{\"consumer\":\"ssh_keygen\",\"setting\":\"SSH_AUTH_SOCK\",\"source\":\
                 {\"kind\":\"environment\"}}",
                "{\"consumer\":\"git\",\"setting\":\"core.sshCommand\",\"source\":\
                 {\"kind\":\"git_scope\",\"scope\":\"command\"}}",
            ]
        );
        for (scope, wire) in [
            (GitScope::System, "system"),
            (GitScope::Global, "global"),
            (GitScope::Local, "local"),
            (GitScope::Worktree, "worktree"),
            (GitScope::Command, "command"),
        ] {
            assert_eq!(git_scope(scope), Some(wire));
        }
    }

    #[test]
    fn strings_are_escaped_as_serde_json_does_and_stay_on_one_line() {
        let mut out = String::new();
        push_json_string(
            &mut out,
            "a\"b\\c\nd\re\tf\u{8}g\u{c}h\u{1}i\u{1f}j\u{7f}k\u{e9}",
        );
        assert_eq!(
            out,
            "\"a\\\"b\\\\c\\nd\\re\\tf\\bg\\fh\\u0001i\\u001fj\u{7f}k\u{e9}\""
        );
        let launching = RunRecord::Launching {
            schema_version: SchemaVersion::current(),
            attempt: 1,
            executable: "/odd\n\"path\"".to_owned(),
            operation_id: None,
            binding_id: None,
            pid: 1,
            consumer_overrides: Vec::new(),
        };
        let text = line(&launching);
        assert_eq!(text.matches('\n').count(), 1);
        assert!(text.ends_with('\n'));
        assert!(text.contains("\"executable\":\"/odd\\n\\\"path\\\"\""));
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

    #[cfg(unix)]
    #[test]
    fn fd_protocol_writes_whole_lines_and_epipe_is_an_error_not_a_signal() {
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

    #[test]
    fn records_written_by_the_channel_classify_as_the_reader_table_says() {
        let dir = Scratch::new();
        let path = dir.path().join("meta.ndjson");
        let mut channel = SideChannel::create_exclusive(&path).unwrap();
        channel.write_launching("/bin/true", &[]).unwrap();
        // Reading back needs the contract's decoder; this crate has none, so the
        // shape is checked through the lines' types and `classify` on equal values.
        let only_launching = [RunRecord::Launching {
            schema_version: SchemaVersion::current(),
            attempt: 1,
            executable: "/bin/true".to_owned(),
            operation_id: None,
            binding_id: None,
            pid: std::process::id(),
            consumer_overrides: Vec::new(),
        }];
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            line(&only_launching[0])
        );
        assert_eq!(
            classify(&only_launching, RunPlatform::Unix),
            LaunchClassification::Indeterminate
        );
    }
}
