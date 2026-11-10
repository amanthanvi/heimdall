//! M01-U8a runtime foundations (m01-plan §1 U8): `Paths::discover`, `Config::{parse,
//! max_window}` and the configuration schema, `InstanceInfo::{write, read_valid}`,
//! `telemetry::{init, redact}`, and `platform::{SystemClock, SystemTimeSync}` on this
//! host. Native sleep/reboot evidence is M04, not here.
//!
//! Hosted by `heimdall-runtime` as `[[test]] integration_runtime`. Every error
//! message, log line and file this suite produces is checked with
//! `heimdall_testkit::assert_no_canary`; canary values are built at run time.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use heimdall_domain::time::{Clock, SyncStatus, TimeSync};
use heimdall_runtime::Paths;
use heimdall_runtime::config::{Config, ConfigError, MAX_CONFIG_BYTES};
use heimdall_runtime::instance::{INSTANCE_FILE, InstanceInfo};
use heimdall_runtime::platform::{self, SystemClock, SystemTimeSync};
use heimdall_runtime::telemetry::{self, MAX_REDACTED_LEN, redact, redact_with_home};
use heimdall_testkit::{CANARY_PREFIX, assert_no_canary};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

/// Small deterministic generator for fixture bytes (no secrets: synthetic data
/// seeded per call site; only its shape matters).
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn from(&mut self, alphabet: &[u8], len: usize) -> String {
        (0..len)
            .map(|_| {
                let i = usize::try_from(self.next() % alphabet.len() as u64).unwrap();
                char::from(alphabet[i])
            })
            .collect()
    }
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const HEX: &[u8] = b"0123456789abcdef";

/// A canary value built at run time, unique per call.
fn canary(tag: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let mut g = Gen(u64::from(nanos) | 1);
    format!("{CANARY_PREFIX}{tag}_{}", g.from(HEX, 24))
}

/// Armor header/footer assembled at run time so no key-looking literal is in the
/// source.
fn armor(kind: &str, begin: bool) -> String {
    let edge = "-".repeat(5);
    let word = if begin { "BEGIN" } else { "END" };
    format!("{edge}{word} {kind} PRIVATE KEY{edge}")
}

fn private_key_block(seed: u64) -> String {
    let mut g = Gen(seed);
    let body: Vec<String> = (0..6).map(|_| g.from(B64, 70)).collect();
    format!(
        "{}\n{}\n{}",
        armor("OPENSSH", true),
        body.join("\n"),
        armor("OPENSSH", false)
    )
}

fn env_from(pairs: Vec<(&'static str, OsString)>) -> impl Fn(&str) -> Option<OsString> {
    move |name| {
        pairs
            .iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.clone())
    }
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::symlink_metadata(path)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

fn parse_err(text: &str) -> ConfigError {
    let err = Config::parse(text).expect_err("config must be refused");
    assert_no_canary(&err.to_string());
    assert_no_canary(&format!("{err:?}"));
    err
}

#[test]
fn config_rejects_trusted_true() {
    let err = parse_err("schema_version = 1\ntrusted = true\n");
    assert!(matches!(err, ConfigError::ForbiddenKey("trusted")), "{err}");
}

#[test]
fn config_rejects_trusted_in_every_place() {
    for text in [
        "schema_version = 1\n[session]\ntrusted = true\n",
        "schema_version = 1\n[x]\ntrusted = true\n",
        "schema_version = 1\n[x.project]\nTRUSTED = true\n",
        "schema_version = 1\n[x]\nlist = [{ trusted = true }]\n",
        "trusted = true\nschema_version = 1\n",
    ] {
        let err = parse_err(text);
        assert!(
            matches!(err, ConfigError::ForbiddenKey("trusted")),
            "{text:?} → {err}"
        );
    }
}

#[test]
fn config_rejects_authority_widening_keys() {
    for (key, expected) in [
        ("private_key", "private_key"),
        ("identity-file", "identity_file"),
        ("socket_path", "socket_path"),
        ("hook", "hook"),
        ("policy_override", "policy_override"),
        ("background_work", "background_work"),
        ("auto_approve", "auto_approve"),
        ("issuing_credential", "issuing_credential"),
        ("enroll", "enroll"),
    ] {
        for text in [
            format!("schema_version = 1\n{key} = \"x\"\n"),
            format!("schema_version = 1\n[x.meta]\n{key} = \"x\"\n"),
        ] {
            let err = parse_err(&text);
            match err {
                ConfigError::ForbiddenKey(k) => assert_eq!(k, expected),
                other => panic!("{key}: expected ForbiddenKey, got {other}"),
            }
        }
    }
}

#[test]
fn config_unknown_ordinary_keys_rejected_outside_x_and_tolerated_inside() {
    let err = parse_err("schema_version = 1\ncolour = \"blue\"\n");
    let msg = err.to_string();
    assert!(matches!(err, ConfigError::Parse(_)));
    assert!(msg.contains("unknown key `colour`"), "{msg}");
    assert!(msg.contains("line 2"), "{msg}");

    let err = parse_err("schema_version = 1\n[session]\nmax_window = \"8h\"\nflavour = 1\n");
    assert!(err.to_string().contains("unknown key `flavour`"), "{err}");

    let c = Config::parse("schema_version = 1\n[x]\nnote = \"hello\"\n[x.editor]\nfold = true\n")
        .unwrap();
    let x = c.x.unwrap();
    assert_eq!(x.get("note").unwrap(), "hello");
}

#[test]
fn config_defaults_and_max_window() {
    let c = Config::parse("schema_version = 1\n").unwrap();
    assert_eq!(c, Config::default());
    assert_eq!(c.max_window().unwrap(), Duration::from_secs(12 * 3600));

    let c = Config::parse("schema_version = 1\n[session]\nmax_window = \"8h\"\nlock_behavior = \"revoke\"\nstrict_disconnect = true\n").unwrap();
    assert_eq!(c.max_window().unwrap(), Duration::from_secs(8 * 3600));
    assert_eq!(
        c.session.lock_behavior,
        heimdall_runtime::config::LockBehavior::Revoke
    );
    assert!(c.session.strict_disconnect);

    let c = Config::parse("schema_version = 1\n[session]\nmax_window = \"PT1H30M\"\n").unwrap();
    assert_eq!(c.max_window().unwrap(), Duration::from_secs(5400));

    let c =
        Config::parse("schema_version = 1\n[retention]\noperations = \"48h\"\nevents = \"2d\"\n")
            .unwrap();
    assert_eq!(
        c.retention_operations().unwrap(),
        Duration::from_secs(48 * 3600)
    );
    assert_eq!(
        c.retention_events().unwrap(),
        Duration::from_secs(2 * 86400)
    );
}

#[test]
fn config_rejects_bad_versions_and_durations() {
    assert!(matches!(
        parse_err("schema_version = 2\n"),
        ConfigError::UnsupportedVersion(2)
    ));
    // A newer file reports its version even when it carries newer keys.
    assert!(matches!(
        parse_err("schema_version = 3\nnew_feature = true\n"),
        ConfigError::UnsupportedVersion(3)
    ));
    assert!(matches!(parse_err(""), ConfigError::Parse(_)));
    assert!(matches!(
        parse_err("schema_version = \"1\"\n"),
        ConfigError::Parse(_)
    ));
    assert!(matches!(
        parse_err("schema_version = -1\n"),
        ConfigError::UnsupportedVersion(_)
    ));
    for window in ["0s", "-1h", "banana", "1 fortnight", ""] {
        let err = parse_err(&format!(
            "schema_version = 1\n[session]\nmax_window = \"{window}\"\n"
        ));
        assert!(
            matches!(
                err,
                ConfigError::Duration {
                    field: "session.max_window",
                    ..
                }
            ),
            "{window:?} → {err}"
        );
    }
    // Retention below the idempotency floor (24 h) is refused (ADR-0006 §7.4).
    let err = parse_err("schema_version = 1\n[retention]\noperations = \"1h\"\nevents = \"7d\"\n");
    assert!(matches!(
        err,
        ConfigError::Duration {
            field: "retention.operations",
            ..
        }
    ));
    let err = parse_err("schema_version = 1\n[retention]\noperations = \"7d\"\nevents = \"0s\"\n");
    assert!(matches!(
        err,
        ConfigError::Duration {
            field: "retention.events",
            ..
        }
    ));
    // Oversized input is refused before parsing.
    let big = format!("schema_version = 1\n# {}\n", "a".repeat(MAX_CONFIG_BYTES));
    assert!(matches!(parse_err(&big), ConfigError::Parse(_)));
}

#[test]
fn config_errors_never_echo_values() {
    let c = canary("cfg");
    for text in [
        format!("schema_version = 1\n[session]\nmax_window = \"{c}\"\n"),
        format!("schema_version = 1\n[session]\nlock_behavior = \"{c}\"\n"),
        format!("schema_version = 1\n[session]\nstrict_disconnect = \"{c}\"\n"),
        format!("schema_version = 1\nbroken = {c}\n"),
        format!("schema_version = 1\n{c} = 1\n"),
        format!("schema_version = 1\n[session]\n{c} = 1\n"),
        format!("schema_version = 1\ntrusted = \"{c}\"\n"),
        format!("schema_version = \"{c}\"\n"),
        format!("schema_version = 1\n[retention]\noperations = \"{c}\"\nevents = \"7d\"\n"),
    ] {
        // parse_err runs assert_no_canary over Display and Debug.
        let _ = parse_err(&text);
    }
}

fn schema_file() -> PathBuf {
    // The repository through HM_REPO_ROOT (ADR-0007 §12.32 item 3).
    heimdall_testkit::repo::repo_path("schemas/configuration/config.schema.json")
}

/// The checked-in `schemas/configuration/config.schema.json` is exactly the
/// generated schema (same rendering as `schemas/public-api/`). Regenerate with
/// `HEIMDALL_BLESS_SCHEMAS=1 cargo test -p heimdall-runtime --test
/// integration_runtime config_schema`.
#[test]
fn config_schema_export_matches_checked_in_file() {
    let generated = Config::json_schema_text().unwrap();
    assert_eq!(
        generated,
        Config::json_schema_text().unwrap(),
        "deterministic"
    );
    let path = schema_file();
    if std::env::var_os("HEIMDALL_BLESS_SCHEMAS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path).expect("schemas/configuration/config.schema.json");
    assert_eq!(
        on_disk, generated,
        "config schema is stale; regenerate (see test docs)"
    );

    let v: serde_json::Value = serde_json::from_str(&generated).unwrap();
    assert_eq!(v["additionalProperties"], serde_json::Value::Bool(false));
    let props = v["properties"].as_object().unwrap();
    assert!(props.contains_key("schema_version"));
    assert!(!props.contains_key("trusted"));
    assert!(
        v["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "schema_version")
    );
}

// ---------------------------------------------------------------------------
// Redaction and logging
// ---------------------------------------------------------------------------

#[test]
fn redact_removes_canaries_wherever_they_appear() {
    let c = canary("redact");
    for text in [
        c.clone(),
        format!("token={c}"),
        format!("{{\"secret\":\"{c}\"}}"),
        format!("/tmp/x/{c}/file"),
        format!("error: value '{c}' rejected"),
        format!("a{c}b"),
    ] {
        let out = redact(&text);
        assert_no_canary(&out);
        assert!(out.contains("[REDACTED]"), "{text:?} → {out:?}");
    }
}

#[test]
fn redact_removes_private_key_blocks() {
    let block = private_key_block(0x9e37_79b9_7f4a_7c15);
    let text = format!("before\n{block}\nafter");
    let out = redact_with_home(&text, None);
    assert!(!out.contains("PRIVATE KEY"), "{out}");
    assert!(out.starts_with("before\n"), "{out}");
    assert!(out.ends_with("\nafter"), "{out}");
    assert!(out.contains("[REDACTED KEY MATERIAL]"));
    // Every body line is gone.
    for line in block.lines().skip(1).take(6) {
        assert!(!out.contains(line));
    }

    // Unterminated block: everything after BEGIN is removed.
    let cut: String = block.lines().take(3).collect::<Vec<_>>().join("\n");
    let out = redact_with_home(&format!("x {cut}"), None);
    assert_eq!(out, "x [REDACTED KEY MATERIAL]");

    // Two blocks and a non-OpenSSH kind.
    let rsa = format!("{}\nAAAA\n{}", armor("RSA", true), armor("RSA", false));
    let out = redact_with_home(&format!("{block} mid {rsa} end"), None);
    assert_eq!(
        out,
        "[REDACTED KEY MATERIAL] mid [REDACTED KEY MATERIAL] end"
    );

    // PuTTY key file.
    let out = redact_with_home(
        "k: PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\nAAAA",
        None,
    );
    assert_eq!(out, "k: [REDACTED KEY MATERIAL]");
}

#[test]
fn redact_removes_key_like_runs_without_prefix_lists() {
    let mut g = Gen(0x2545_f491_4f6c_dd1d);
    let b64 = g.from(B64, 43);
    let url = g.from(B64URL, 40);
    let hex = g.from(HEX, 64);
    let wrapped = format!("{}==", g.from(B64, 30));
    for secret in [&b64, &url, &hex, &wrapped] {
        let text = format!("got credential {secret} from agent");
        let out = redact_with_home(&text, None);
        assert_eq!(out, "got credential [REDACTED] from agent", "{secret}");
    }
    // Inside a path segment.
    let out = redact_with_home(&format!("/var/tmp/{hex}/x"), None);
    assert_eq!(out, "/var/tmp/[REDACTED]/x");
}

/// Deterministic randomized check (fixed seed, 2048 cases; the runtime crate has
/// no proptest edge): random base64/base64url/hex key material of 24–96
/// characters, in several embeddings, never leaves a 12-character piece behind.
#[test]
fn redact_random_key_material_never_survives() {
    let mut g = Gen(0x5851_f42d_4c95_7f2d);
    for case in 0..2048u64 {
        let alphabet = match case % 3 {
            0 => B64,
            1 => B64URL,
            _ => HEX,
        };
        let min = if alphabet == HEX { 32 } else { 24 };
        let len = min + usize::try_from(g.next() % 73).unwrap();
        let secret = g.from(alphabet, len);
        for text in [
            format!("value {secret} end"),
            format!("/tmp/run/{secret}/file"),
            format!("key={secret}"),
            format!("\"{secret}\""),
        ] {
            let out = redact_with_home(&text, None);
            let chars: Vec<char> = secret.chars().collect();
            for w in chars.windows(12) {
                let piece: String = w.iter().collect();
                assert!(
                    !out.contains(&piece),
                    "case {case}: piece of {secret:?} survived in {out:?}"
                );
            }
        }
    }
}

#[test]
fn redact_keeps_ordinary_diagnostics() {
    let id = format!("op_{}", Gen(7).from(HEX, 32));
    for text in [
        format!("operation {id} failed: connection refused"),
        "/usr/local/bin/heimdall service run --detach".to_owned(),
        "heimdall_runtime::supervisor::scheduler_pass took 3ms".to_owned(),
        "SCHEMA_UNSUPPORTED: protocol major 2 is newer than 1".to_owned(),
        "2026-10-31T12:00:00Z grant expired at deadline".to_owned(),
        "ssh-ed25519 key comment".to_owned(),
    ] {
        assert_eq!(redact_with_home(&text, None), text);
    }
}

#[test]
fn redact_removes_home_paths() {
    let cases = [
        ("/Users/example-user/projects/a.toml", "~/projects/a.toml"),
        (
            "open /home/example-user/.ssh/config failed",
            "open ~/.ssh/config failed",
        ),
        (
            r"C:\Users\example-user\AppData\Local\heimdall",
            r"~\AppData\Local\heimdall",
        ),
        ("cwd=/root/work", "cwd=~/work"),
        ("dir \"/home/example-user\" missing", "dir \"~\" missing"),
        ("/var/home/example-user/x", "/var~/x"),
    ];
    for (input, expected) in cases {
        assert_eq!(redact_with_home(input, None), expected, "{input}");
    }
    // The real home directory, wherever it is, by exact match.
    let out = redact_with_home("/opt/people/somebody/file", Some("/opt/people/somebody"));
    assert_eq!(out, "~/file");
    if let Ok(home) = etcetera::home_dir() {
        let text = format!("{}/x", home.display());
        assert_eq!(redact(&text), "~/x");
    }
}

#[test]
fn redact_bounds_length() {
    let text = "word ".repeat(5000);
    let out = redact(&text);
    assert!(out.len() <= MAX_REDACTED_LEN, "{}", out.len());
    assert!(out.ends_with("…[truncated]"));
    let multibyte = "é".repeat(MAX_REDACTED_LEN);
    let out = redact(&multibyte);
    assert!(out.len() <= MAX_REDACTED_LEN);
}

/// The only test that installs the global subscriber (it is process-wide).
#[test]
fn log_file_sink_redacts_every_line() {
    let dir = tempfile::tempdir().unwrap();
    telemetry::init(telemetry::LogSink::File, Some(dir.path())).unwrap();
    // Idempotent.
    telemetry::init(telemetry::LogSink::File, Some(dir.path())).unwrap();
    let c = canary("log");
    let block = private_key_block(0x1234_5678_9abc_def1);
    tracing::warn!(value = %c, "u8a-log-probe structured field");
    tracing::warn!("u8a-log-probe message {c} and key {block}");
    let path = dir.path().join(telemetry::LOG_FILE);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.contains("u8a-log-probe structured field"), "{text}");
    assert!(text.contains("u8a-log-probe message [REDACTED]"), "{text}");
    assert!(!text.contains("PRIVATE KEY"), "{text}");
    assert!(!text.contains('\u{1b}'), "no ANSI escapes");
    assert_no_canary(&text);
    #[cfg(unix)]
    assert_eq!(mode_of(&path), 0o600);
}

#[test]
fn log_file_sink_needs_a_directory() {
    // Whatever the global state, a File sink without a directory never panics;
    // before installation it is an error, after installation a no-op.
    let r = telemetry::init(telemetry::LogSink::File, None);
    if let Err(e) = r {
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput);
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

#[test]
fn paths_heimdall_home_layout_is_owner_only() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("hh");
    let env = env_from(vec![("HEIMDALL_HOME", home.clone().into_os_string())]);
    let p = Paths::discover_from(&env).unwrap();
    assert_eq!(p, Paths::under(&home));
    for dir in [&p.config_dir, &p.state_dir, &p.runtime_dir, &p.log_dir] {
        assert!(dir.starts_with(&home));
        assert!(std::fs::symlink_metadata(dir).unwrap().is_dir());
        #[cfg(unix)]
        assert_eq!(mode_of(dir), 0o700, "{}", dir.display());
    }
    // Idempotent.
    assert_eq!(Paths::discover_from(&env).unwrap(), p);
}

#[test]
fn paths_refuse_relative_or_empty_heimdall_home() {
    for value in ["relative/dir", ""] {
        let env = env_from(vec![("HEIMDALL_HOME", OsString::from(value))]);
        let err = Paths::resolve(&env).expect_err("must refuse");
        assert!(err.to_string().contains("HEIMDALL_HOME"), "{err}");
    }
}

#[cfg(unix)]
#[test]
fn paths_tighten_existing_permissive_dirs_and_refuse_symlinks() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("hh");
    let layout = Paths::under(&home);
    std::fs::create_dir_all(&layout.state_dir).unwrap();
    std::fs::set_permissions(&layout.state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    layout.ensure().unwrap();
    assert_eq!(mode_of(&layout.state_dir), 0o700);

    // A symlink at a leaf is refused, and its target is left untouched.
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir(&layout.log_dir).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &layout.log_dir).unwrap();
    let err = layout
        .ensure()
        .expect_err("symlinked log dir must be refused");
    assert!(
        matches!(err, ConfigError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "{err}"
    );
    assert_eq!(mode_of(&elsewhere), 0o755);

    // A regular file where a directory belongs is refused.
    std::fs::remove_file(&layout.log_dir).unwrap();
    std::fs::write(&layout.log_dir, b"").unwrap();
    assert!(layout.ensure().is_err());
}

#[cfg(unix)]
#[test]
fn paths_platform_defaults_follow_xdg() {
    let env = env_from(vec![
        ("XDG_CONFIG_HOME", OsString::from("/xdg/config")),
        ("XDG_STATE_HOME", OsString::from("/xdg/state")),
        ("XDG_RUNTIME_DIR", OsString::from("/xdg/run")),
    ]);
    let p = Paths::resolve(&env).unwrap();
    assert_eq!(p.config_dir, Path::new("/xdg/config/heimdall"));
    assert_eq!(p.state_dir, Path::new("/xdg/state/heimdall"));
    assert_eq!(p.runtime_dir, Path::new("/xdg/run/heimdall"));
    assert_eq!(p.log_dir, Path::new("/xdg/state/heimdall/log"));

    // Relative XDG values are ignored (XDG spec); no runtime dir → under state.
    let env = env_from(vec![("XDG_CONFIG_HOME", OsString::from("rel/config"))]);
    let p = Paths::resolve(&env).unwrap();
    let home = etcetera::home_dir().unwrap();
    assert_eq!(p.config_dir, home.join(".config").join("heimdall"));
    assert_eq!(p.state_dir, home.join(".local/state/heimdall"));
    assert_eq!(p.runtime_dir, home.join(".local/state/heimdall/run"));
}

// ---------------------------------------------------------------------------
// Instance info
// ---------------------------------------------------------------------------

fn runtime_dir(tmp: &tempfile::TempDir) -> PathBuf {
    let layout = Paths::under(&tmp.path().join("hh"));
    layout.ensure().unwrap();
    layout.runtime_dir
}

fn info_for(dir: &Path, pid: u32, started_at: String) -> InstanceInfo {
    InstanceInfo {
        pid,
        started_at,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        control_endpoint: dir.join("control.sock").display().to_string(),
        signing_endpoint: dir.join("signing.sock").display().to_string(),
    }
}

#[cfg(unix)]
fn listen(
    dir: &Path,
) -> (
    std::os::unix::net::UnixListener,
    std::os::unix::net::UnixListener,
) {
    use std::os::unix::fs::PermissionsExt as _;
    let bind = |name: &str| {
        let path = dir.join(name);
        let l = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        l
    };
    (bind("control.sock"), bind("signing.sock"))
}

#[test]
fn instance_write_is_atomic_and_owner_only() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = runtime_dir(&tmp);
    let info = info_for(&dir, 4242, "1.000001".to_owned());
    info.write(&dir).unwrap();
    // Overwrite with a second record: the reader sees exactly the new one.
    let second = InstanceInfo {
        pid: 4343,
        ..info.clone()
    };
    second.write(&dir).unwrap();
    assert_eq!(InstanceInfo::read_file(&dir).unwrap(), Some(second));
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec![INSTANCE_FILE.to_owned()], "no temp files left");
    #[cfg(unix)]
    assert_eq!(mode_of(&dir.join(INSTANCE_FILE)), 0o600);
    assert_no_canary(&std::fs::read_to_string(dir.join(INSTANCE_FILE)).unwrap());
}

#[cfg(unix)]
#[test]
fn instance_valid_when_process_and_endpoints_are_live() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = runtime_dir(&tmp);
    let (_c, _s) = listen(&dir);
    let started = InstanceInfo::current_started_at().expect("start time on this host");
    let info = info_for(&dir, std::process::id(), started);
    info.write(&dir).unwrap();
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), Some(info));
}

#[cfg(unix)]
#[test]
fn instance_stale_records_are_ignored() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = runtime_dir(&tmp);
    let me = std::process::id();
    let started = InstanceInfo::current_started_at().unwrap();

    // Absent.
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), None);

    // Live endpoints, but a start time that does not match (PID reuse).
    let (c, s) = listen(&dir);
    info_for(&dir, me, "0.000000".to_owned())
        .write(&dir)
        .unwrap();
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), None);
    info_for(&dir, me, String::new()).write(&dir).unwrap();
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), None);

    // A process that has exited (started and reaped by this test).
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "exit 0"])
        .spawn()
        .unwrap();
    let child_pid = child.id();
    let child_start = platform::process_start_time(child_pid);
    child.wait().unwrap();
    assert_eq!(
        platform::process_start_time(child_pid).filter(|s| Some(s) == child_start.as_ref()),
        None
    );
    info_for(&dir, child_pid, child_start.unwrap_or_else(|| "1.0".into()))
        .write(&dir)
        .unwrap();
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), None);

    // Endpoints advertised somewhere else than this runtime directory.
    let mut elsewhere = info_for(&dir, me, started.clone());
    elsewhere.control_endpoint = tmp.path().join("control.sock").display().to_string();
    elsewhere.write(&dir).unwrap();
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), None);

    // Valid now …
    let live = info_for(&dir, me, started.clone());
    live.write(&dir).unwrap();
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), Some(live.clone()));
    // … stale once the listeners are gone (socket files remain, connect refused).
    drop((c, s));
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), None);
    assert!(
        dir.join("control.sock").exists(),
        "read_valid never deletes"
    );

    // Malformed and oversized files.
    std::fs::write(dir.join(INSTANCE_FILE), b"{not json").unwrap();
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), None);
    std::fs::write(dir.join(INSTANCE_FILE), vec![b' '; 70 * 1024]).unwrap();
    assert_eq!(InstanceInfo::read_valid(&dir).unwrap(), None);
}

#[cfg(unix)]
#[test]
fn instance_insecure_files_are_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let tmp = tempfile::tempdir().unwrap();
    let dir = runtime_dir(&tmp);
    let info = info_for(&dir, std::process::id(), "x".to_owned());
    info.write(&dir).unwrap();
    let path = dir.join(INSTANCE_FILE);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let err = InstanceInfo::read_valid(&dir).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_no_canary(&err.to_string());

    // A symlink in place of the file is never followed.
    std::fs::remove_file(&path).unwrap();
    let target = tmp.path().join("target.json");
    std::fs::write(&target, serde_json::to_vec(&info).unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(InstanceInfo::read_valid(&dir).is_err());
}

// ---------------------------------------------------------------------------
// Platform clock on this host (native sleep/reboot is M04)
// ---------------------------------------------------------------------------

#[test]
fn system_clock_probes_on_this_host() {
    SystemClock::try_new().expect("continuous clock and boot ID available on this host");
}

#[test]
fn system_clock_continuous_is_monotonic_and_tracks_elapsed_time() {
    let clock = SystemClock::new();
    let start = Instant::now();
    let a = clock.continuous();
    let mut prev = a;
    // A sleep-free interval of about 100 ms, sampled densely.
    while start.elapsed() < Duration::from_millis(100) {
        let now = clock.continuous();
        assert!(now >= prev, "continuous clock went backwards");
        prev = now;
        std::thread::sleep(Duration::from_millis(5));
    }
    let b = clock.continuous();
    let elapsed = start.elapsed();
    let advanced = b.checked_sub(a).expect("monotonic");
    assert!(advanced >= Duration::from_millis(90), "{advanced:?}");
    let diff = advanced.abs_diff(elapsed);
    assert!(
        diff < Duration::from_millis(50),
        "continuous {advanced:?} vs elapsed {elapsed:?}"
    );
    // Boot-scoped and counting from boot: at least as large as this process's
    // own runtime.
    assert!(a > Duration::ZERO);
}

#[test]
fn system_clock_boot_id_is_stable_across_reads() {
    let first = platform::read_boot_id_uncached().expect("boot ID");
    let second = platform::read_boot_id_uncached().expect("boot ID");
    assert_eq!(first, second);
    assert!(!first.is_empty());
    let clock = SystemClock::new();
    assert_eq!(clock.boot_id().0, first);
    assert_eq!(clock.boot_id(), clock.boot_id());
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        assert_eq!(first.len(), 36, "UUID form");
        assert!(first.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        assert!(!first.starts_with("unavailable:"));
    }
    let obs = clock.observe();
    assert_eq!(obs.boot_id.0, first);
    let wall_secs = obs.wall.as_second();
    let sys = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(i64::try_from(sys).unwrap().abs_diff(wall_secs) <= 2);
}

#[test]
fn process_start_time_identifies_this_process() {
    let a = platform::process_start_time(std::process::id()).expect("own start time");
    let b = platform::process_start_time(std::process::id()).unwrap();
    assert_eq!(a, b);
    assert_eq!(platform::process_start_time(0), None);
    assert_eq!(platform::process_start_time(u32::MAX), None);
}

/// An exited process that its parent has not reaped yet (a zombie) is not
/// alive: `service stop` waits for the advertised runtime to end, and a test (or
/// any parent) that reaps its child only after the stop would otherwise make
/// every stop time out (observed natively on Linux, where `/proc/<pid>/stat`
/// outlives the exit until the reap).
#[cfg(unix)]
#[test]
fn process_start_time_treats_an_unreaped_exited_child_as_gone() {
    use std::io::Read as _;
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "read -r _; exit 0"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id();
    let started = platform::process_start_time(pid);
    assert!(started.is_some(), "a running child has a start time");
    // Let it exit, then wait for its stdout to close (it has exited) without
    // reaping it.
    drop(child.stdin.take());
    let mut sink = Vec::new();
    child.stdout.take().unwrap().read_to_end(&mut sink).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut gone = false;
    while Instant::now() < deadline {
        if platform::process_start_time(pid) != started {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait().unwrap();
    assert!(gone, "an exited, unreaped child still looks alive");
}

#[test]
fn system_time_sync_is_unknown_in_m01() {
    // Fail-closed default (ADR-0006 §10): no platform signal is trusted yet.
    assert_eq!(SystemTimeSync.status(), SyncStatus::Unknown);
}

// ===========================================================================
// M01-U8b: service start/run, supervisor (scheduler, time guard), launcher, and
// the control-endpoint dispatcher over `Operations`.
//
// Restart label: every "restart" below is an **in-process** reconstruction (a
// new `Service` over the same `HEIMDALL_HOME` layout, store file and fake-adapter
// ledger file); it is not process-crash evidence (that is U9/U10's, ADR-0006
// §13.4 N06). The launcher test starts a real child process (this test binary
// re-executed as a service host), not the `heimdall` binary (U9's e2e suite).
// ===========================================================================

mod u8b {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use heimdall_app::ports::{
        AdapterDescriptor, CredentialAdapter, InteractionRequirement, LockContinuity,
        PrepareOutcome,
    };
    use heimdall_app::{Caller, OpError, OpResult};
    use heimdall_contract::envelope::Envelope;
    use heimdall_contract::ids::{
        AccountName, DestinationId, DeviceId, EnvironmentId, PolicyId, ProfileId, RequestId, WorkId,
    };
    use heimdall_contract::ipc::PrincipalInfo;
    use heimdall_contract::request::{
        DeadlineIntent, DestinationScopeEnforcement, Enforcement, EnsureData, EnsureRequest,
        ExistingConnectionsPolicy, InteractionMode, NewAuthenticationExpiry, PolicyAction,
        RefreshDependency, RequiredCapabilities, RevocationStatus, WaitMode, WorkloadIsolation,
    };
    use heimdall_contract::{Code, GrantState, OperationState, Timestamp};
    use heimdall_domain::environment::{
        EnvironmentKind, EnvironmentPermissions, EnvironmentRecord,
    };
    use heimdall_domain::evidence::EnforcementEvidence;
    use heimdall_domain::operation::{AdapterIdentity, EffectReceipt};
    use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
    use heimdall_domain::principal::{CallerContext, ClientRole, PrincipalRef};
    use heimdall_domain::profile::ProfileDefinition;
    use heimdall_domain::scope::{AccessPair, Capability, Scope};
    use heimdall_domain::time::{SyncStatus, TimeStatus, TimeUncertainty};
    use heimdall_ipc::session::SessionInfo;
    use heimdall_runtime::Paths;
    use heimdall_runtime::config::Config;
    use heimdall_runtime::dispatch::caller_for;
    use heimdall_runtime::instance::{INSTANCE_FILE, InstanceError, InstanceInfo};
    use heimdall_runtime::launcher::{LaunchError, LauncherConfig, Started, ensure_running_with};
    use heimdall_runtime::service::{STATE_DB_FILE, Service, ServiceError, ServiceOptions};
    use heimdall_store::{FaultAction, FaultHook, FaultPoint, NoFaults, Store};
    use heimdall_testkit::{
        CANARY_PREFIX, FakeCredentialAdapter, FakeStep, ScriptedTimeSync, VirtualClock,
        assert_no_canary,
    };
    use tokio_util::sync::CancellationToken;

    const MINUTE: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_secs(3600);

    fn t0() -> Timestamp {
        "2026-10-02T09:00:00Z".parse().unwrap()
    }

    fn at(secs: i64) -> Timestamp {
        t0().checked_add(jiff::SignedDuration::from_secs(secs))
            .unwrap()
    }

    fn env_id() -> EnvironmentId {
        EnvironmentId::from_random_bytes([7; 16])
    }

    /// Synthetic canary built at run time: the fake adapter's opaque credential
    /// reference. It must never reach an envelope, event or error.
    fn canary() -> String {
        format!("{CANARY_PREFIX}u8b_fixture")
    }

    fn pair(d: &str, a: &str) -> AccessPair {
        AccessPair {
            destination: DestinationId::parse(d).unwrap(),
            account: AccountName::parse(a).unwrap(),
        }
    }

    fn ssh_only() -> BTreeSet<Capability> {
        [Capability::SshAuthentication].into_iter().collect()
    }

    fn enforcement() -> EnforcementEvidence {
        EnforcementEvidence {
            report: Enforcement {
                destination_scope: DestinationScopeEnforcement::ClientRouting,
                new_authentication_expiry: NewAuthenticationExpiry::SignerOnly,
                workload_isolation: WorkloadIsolation::SharedOsUser,
                existing_connections: ExistingConnectionsPolicy::GracefulDedicatedConnections,
                revocation: RevocationStatus::LocalApplied,
                // M03 wave 0 (A1): fail closed until U0b
                identity_selection: None,
                new_signing_expiry: None,
                owned_multiplexing: None,
                remote_processes: None,
                unmanaged_connections: None,
                issuer_isolation: None,
            },
            evidence: Vec::new(),
        }
    }

    fn outcome() -> PrepareOutcome {
        PrepareOutcome {
            usable_until: at(12 * 3600),
            offline_until: at(3600),
            refresh_dependency: RefreshDependency::None,
            enforcement: enforcement(),
            credential_ref: canary(),
            availability: Default::default(),
            provider: None,
            integration: Default::default(),
        }
    }

    fn descriptor() -> AdapterDescriptor {
        AdapterDescriptor {
            identity: AdapterIdentity {
                mechanism: "fake_agent".into(),
                instance: "fixture-1".into(),
            },
            capabilities: ssh_only(),
            external_side_effects: false,
            interaction: InteractionRequirement::None,
            enforcement: enforcement(),
            lock_continuity: LockContinuity::Unknown,
            remote_credential_effect: false, // M03 wave 0 (A2)
        }
    }

    fn policy_id() -> PolicyId {
        PolicyId::parse("pol").unwrap()
    }

    /// `HEIMDALL_HOME` layout inside the test's own temp dir.
    fn home(tmp: &tempfile::TempDir) -> PathBuf {
        tmp.path().join("hh")
    }

    /// Seed the store file a service will open: identity, environment record,
    /// profile `dev` (h1, h2, h3) and policy `pol` (h1, h2; window 2 h).
    fn seed(home: &Path) {
        let paths = Paths::under(home);
        paths.ensure().unwrap();
        let store = Store::open(&paths.state_dir.join(STATE_DB_FILE), Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                tx.init_self_environment(&env_id())?;
                tx.upsert_environment(&EnvironmentRecord {
                    id: env_id(),
                    device: DeviceId::from_random_bytes([8; 16]),
                    kind: EnvironmentKind::NativeSession,
                    label: None,
                    permissions: EnvironmentPermissions {
                        automatic_activation: true,
                        managed_signing: true,
                        issuer_access: true,
                    },
                })?;
                tx.upsert_profile(&ProfileDefinition {
                    id: ProfileId::parse("dev").unwrap(),
                    revision: 1,
                    scope: Scope {
                        pairs: [
                            pair("h1", "deploy"),
                            pair("h2", "deploy"),
                            pair("h3", "deploy"),
                        ]
                        .into_iter()
                        .collect(),
                        capabilities: ssh_only(),
                    },
                    label: None,
                })?;
                tx.upsert_policy(
                    &StandingPolicy {
                        id: policy_id(),
                        revision: PolicyRevision(1),
                        profile: ProfileId::parse("dev").unwrap(),
                        workspace: None,
                        scope: Scope {
                            pairs: [pair("h1", "deploy"), pair("h2", "deploy")]
                                .into_iter()
                                .collect(),
                            capabilities: ssh_only(),
                        },
                        environments: [env_id()].into_iter().collect(),
                        max_window: 2 * HOUR,
                        pause: PauseState::Active,
                        cutoff_at: None,
                        source: PolicySource::SetupDefault,
                        // M03 wave 0 (A1): fail closed until U0b
                        lock_behavior: Default::default(),
                        connection: Default::default(),
                    },
                    false,
                )?;
                Ok(())
            })
            .unwrap();
    }

    struct Rig {
        home: PathBuf,
        clock: Arc<VirtualClock>,
        sync: Arc<ScriptedTimeSync>,
        ledger: PathBuf,
    }

    impl Rig {
        fn new(tmp: &tempfile::TempDir) -> Self {
            let home = home(tmp);
            seed(&home);
            Self {
                home,
                clock: VirtualClock::at(t0()),
                sync: ScriptedTimeSync::new(SyncStatus::Synchronized),
                ledger: tmp.path().join("effects.ledger"),
            }
        }

        fn paths(&self) -> Paths {
            Paths::under(&self.home)
        }

        /// A fresh fake adapter instance over this rig's durable ledger.
        fn fake(&self, script: Vec<FakeStep>) -> Arc<FakeCredentialAdapter> {
            FakeCredentialAdapter::with_ledger(descriptor(), script, &self.ledger).unwrap()
        }

        fn options(&self, fake: &Arc<FakeCredentialAdapter>) -> ServiceOptions {
            let mut o = test_options(self.clock.clone(), self.sync.clone());
            o.adapters = vec![fake.clone() as Arc<dyn CredentialAdapter>];
            o
        }

        async fn start(&self, options: ServiceOptions) -> Result<Service, ServiceError> {
            Service::start_with(
                self.paths(),
                Config::default(),
                options,
                CancellationToken::new(),
            )
            .await
        }

        async fn service(&self) -> Service {
            let fake = self.fake(vec![FakeStep::Prepare(outcome())]);
            self.start(self.options(&fake)).await.unwrap()
        }

        fn ledger_entries(&self) -> usize {
            FakeCredentialAdapter::ledger_entries(&self.ledger)
                .unwrap()
                .len()
        }
    }

    /// Options around the virtual clock; Windows pipes get the `hmtest-` prefix
    /// (recognizable test pipes; the rest of the token stays random).
    fn test_options(clock: Arc<VirtualClock>, sync: Arc<ScriptedTimeSync>) -> ServiceOptions {
        let mut o = ServiceOptions::with_clock(clock, sync);
        o.endpoint_prefix = TEST_PIPE_PREFIX.to_owned();
        o
    }

    /// Windows pipe-name prefix of every service these tests start.
    const TEST_PIPE_PREFIX: &str = "hmtest-";

    fn owner() -> Caller {
        Caller::unattended(CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        })
    }

    fn ensure_req(request_id: &str, work: &str, until: Option<&str>) -> EnsureRequest {
        EnsureRequest {
            profile: ProfileId::parse("dev").unwrap(),
            profile_revision: None,
            scope: [pair("h1", "deploy")].into_iter().collect(),
            environment: None,
            work_id: WorkId::parse(work).unwrap(),
            until: until.map(|u| DeadlineIntent::Duration(u.to_owned())),
            required_capabilities: RequiredCapabilities::default(),
            request_id: RequestId::parse(request_id).unwrap(),
            interaction: InteractionMode::NonInteractive,
            wait: WaitMode::Sync { timeout_ms: 30_000 },
            // M03 wave 0 (A1): fail closed until U0b
            connection: None,
        }
    }

    /// Render a result as its wire envelope, scanning it for canaries.
    fn scanned<T: serde::Serialize + Clone>(r: &OpResult<T>) -> serde_json::Value {
        let v = match r {
            Ok(c) => serde_json::to_value(c.clone().into_envelope()).unwrap(),
            Err(e) => serde_json::to_value(e.clone().into_envelope()).unwrap(),
        };
        assert_no_canary(&v.to_string());
        v
    }

    fn ok<T: serde::Serialize + Clone>(r: OpResult<T>) -> T {
        scanned(&r);
        match r {
            Ok(c) => c.data,
            Err(e) => panic!("expected success, got {}: {}", e.code, e.message),
        }
    }

    fn err<T: serde::Serialize + Clone>(r: OpResult<T>) -> OpError {
        scanned(&r);
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => {
                assert_no_canary(&e.message);
                e
            }
        }
    }

    async fn ensure(svc: &Service, request_id: &str, work: &str, until: &str) -> EnsureData {
        ok(svc
            .operations()
            .ensure(&owner(), ensure_req(request_id, work, Some(until)))
            .await)
    }

    fn grant_state(svc: &Service, data: &EnsureData) -> GrantState {
        svc.store()
            .transaction(|tx| tx.grant(&data.grant_id))
            .unwrap()
            .unwrap()
            .state
    }

    /// Every stored event, scanned for canaries.
    fn scan_events(svc: &Service) {
        let page = svc
            .store()
            .transaction(|tx| {
                tx.stored_events_after(
                    &env_id(),
                    0,
                    &heimdall_contract::event::EventFilter::default(),
                    10_000,
                )
            })
            .unwrap();
        for e in &page.events {
            assert_no_canary(&serde_json::to_string(&e.event).unwrap());
        }
    }

    // -----------------------------------------------------------------------
    // Single instance and the advertisement
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn service_second_start_is_already_running() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let first = rig.service().await;
        let advertised = InstanceInfo::read_file(&rig.paths().runtime_dir)
            .unwrap()
            .unwrap();
        assert_eq!(&advertised, first.instance());
        assert_eq!(advertised.pid, std::process::id());

        let fake = rig.fake(vec![FakeStep::Prepare(outcome())]);
        let second = rig.start(rig.options(&fake)).await;
        assert!(
            matches!(
                second,
                Err(ServiceError::Instance(InstanceError::AlreadyRunning))
            ),
            "second start must be refused"
        );
        // The refused start touched neither the advertisement nor the endpoints.
        assert_eq!(
            InstanceInfo::read_file(&rig.paths().runtime_dir).unwrap(),
            Some(advertised)
        );
        assert_eq!(
            InstanceInfo::read_valid(&rig.paths().runtime_dir)
                .unwrap()
                .as_ref(),
            Some(first.instance())
        );
        #[cfg(windows)]
        assert!(
            first
                .instance()
                .control_endpoint
                .starts_with(&format!(r"\\.\pipe\heimdall-{TEST_PIPE_PREFIX}")),
            "test pipes carry the test prefix"
        );

        // Dropping the first releases the lock and removes its advertisement and
        // endpoints (sockets unlinked; pipes closed); a new start then succeeds.
        let endpoints = first.endpoints().clone();
        drop(first);
        assert!(!rig.paths().runtime_dir.join(INSTANCE_FILE).exists());
        assert_endpoints_gone(&endpoints).await;
        let third = rig.service().await;
        assert_eq!(third.environment(), &env_id());
    }

    /// No advertised endpoint answers any more: Unix socket files unlinked;
    /// Windows pipes closed (opening the name fails).
    async fn assert_endpoints_gone(endpoints: &heimdall_ipc::EndpointPaths) {
        #[cfg(unix)]
        assert!(!endpoints.control.exists() && !endpoints.signing.exists());
        #[cfg(windows)]
        for pipe in [&endpoints.control, &endpoints.signing] {
            assert!(
                heimdall_ipc::windows::connect(pipe).await.is_err(),
                "the pipe is gone"
            );
        }
    }

    /// A crashed instance's record (its start time does not match: PID reuse; on
    /// Unix also a dead socket at the control path) is ignored, never trusted, and
    /// replaced by the next start; a client that may not start anything sees "not
    /// running". Runs on Unix and Windows (ADR-0006 §13.6 item 8).
    #[tokio::test]
    async fn service_ignores_and_replaces_a_stale_instance_json() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let run = rig.paths().runtime_dir;
        #[cfg(unix)]
        let (control, signing) = (
            run.join("control.sock").display().to_string(),
            run.join("signing.sock").display().to_string(),
        );
        #[cfg(windows)]
        let (control, signing) = (
            format!(r"\\.\pipe\heimdall-{TEST_PIPE_PREFIX}stale-control"),
            format!(r"\\.\pipe\heimdall-{TEST_PIPE_PREFIX}stale-signing"),
        );
        let stale = InstanceInfo {
            pid: std::process::id(),
            started_at: "0.000000".to_owned(),
            version: "0.0.0".to_owned(),
            control_endpoint: control,
            signing_endpoint: signing,
        };
        stale.write(&run).unwrap();
        #[cfg(unix)]
        {
            drop(std::os::unix::net::UnixListener::bind(run.join("control.sock")).unwrap());
            assert!(run.join("control.sock").exists());
        }
        assert_eq!(InstanceInfo::read_valid(&run).unwrap(), None);

        // A client that may not start anything sees "not running", not the record.
        let spawned = AtomicUsize::new(0);
        let spawn = || {
            spawned.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let r = ensure_running_with(&run, false, LauncherConfig::default(), &spawn).await;
        assert!(matches!(r, Err(LaunchError::NotRunning)));
        assert_eq!(spawned.load(Ordering::SeqCst), 0);

        let fake = rig.fake(vec![FakeStep::Prepare(outcome())]);
        let token = CancellationToken::new();
        let svc = Service::start_with(
            rig.paths(),
            Config::default(),
            rig.options(&fake),
            token.clone(),
        )
        .await
        .unwrap();
        let now = InstanceInfo::read_valid(&run).unwrap().unwrap();
        assert_eq!(&now, svc.instance());
        let running = tokio::spawn(svc.run());
        assert_ne!(now.started_at, stale.started_at);
        #[cfg(windows)]
        assert_ne!(now.control_endpoint, stale.control_endpoint);
        // Now the launcher finds it without spawning.
        let r = ensure_running_with(&run, true, LauncherConfig::default(), &spawn).await;
        assert!(matches!(r, Ok(Started::AlreadyRunning)));
        assert_eq!(spawned.load(Ordering::SeqCst), 0);
        // And a client reaches it at the advertised endpoint.
        let c = control_client(
            Path::new(&now.control_endpoint),
            InteractionMode::NonInteractive,
        )
        .await;
        assert_eq!(c.server().environment_id, env_id());
        drop(c);
        token.cancel();
        running.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn environment_identity_is_created_once_and_never_changes() {
        let tmp = tempfile::tempdir().unwrap();
        // Fresh home, no seeded identity: the first start creates one.
        let paths = Paths::under(&home(&tmp));
        let clock = VirtualClock::at(t0());
        let sync = ScriptedTimeSync::new(SyncStatus::Synchronized);
        let start = || {
            Service::start_with(
                paths.clone(),
                Config::default(),
                test_options(clock.clone(), sync.clone()),
                CancellationToken::new(),
            )
        };
        let first = start().await.unwrap();
        let id = first.environment().clone();
        let recorded = first
            .store()
            .transaction(|tx| tx.self_environment())
            .unwrap();
        assert_eq!(recorded.as_ref(), Some(&id));
        drop(first);
        let second = start().await.unwrap();
        assert_eq!(second.environment(), &id, "restart keeps the identity");
    }

    // -----------------------------------------------------------------------
    // Deadline scheduler under the virtual clock
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn scheduler_expires_exactly_at_the_persisted_bound_across_a_same_boot_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let svc = rig.service().await;
        let data = ensure(&svc, "req-sb", "work-sb", "1h").await;
        assert_eq!(data.expires_at, at(3600));
        let next = svc.supervisor().scheduler_pass().await.unwrap();
        assert_eq!(next, Some(at(3600)), "next wake is the persisted bound");

        rig.clock.advance(20 * MINUTE);
        assert_eq!(
            svc.supervisor().scheduler_pass().await.unwrap(),
            Some(at(3600))
        );
        // In-process same-boot restart: the persisted bound and anchor survive.
        drop(svc);
        let svc = rig.service().await;
        rig.clock.advance(40 * MINUTE - Duration::from_secs(1));
        assert_eq!(
            svc.supervisor().scheduler_pass().await.unwrap(),
            Some(at(3600))
        );
        assert_eq!(grant_state(&svc, &data), GrantState::Active);
        rig.clock.advance(Duration::from_secs(1));
        svc.supervisor().scheduler_pass().await.unwrap();
        assert_eq!(grant_state(&svc, &data), GrantState::Expired);
        // Nothing else is due.
        assert_eq!(svc.supervisor().scheduler_pass().await.unwrap(), None);
        scan_events(&svc);
    }

    #[tokio::test]
    async fn scheduler_expires_at_the_continuous_budget_end_with_the_wall_clock_lagging() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let svc = rig.service().await;
        let data = ensure(&svc, "req-cb", "work-cb", "1h").await;
        // Awake until 30 s before the bound.
        rig.clock.advance(HOUR - Duration::from_secs(30));
        assert_eq!(
            svc.supervisor().scheduler_pass().await.unwrap(),
            Some(at(3600))
        );
        // The wall clock now stalls while continuous time runs (within the skew
        // tolerance, so time stays safe): the budget, not the wall, ends the grant.
        rig.clock.advance_continuous_only(Duration::from_secs(29));
        let next = svc.supervisor().scheduler_pass().await.unwrap();
        assert_eq!(
            next,
            Some(at(3600 - 29)),
            "next wake is the wall instant at which the budget runs out"
        );
        assert_eq!(grant_state(&svc, &data), GrantState::Active);
        // Same-boot restart in between: the budget resumes from the persisted
        // anchor, never rebuilt from the (lagging) wall clock.
        drop(svc);
        let svc = rig.service().await;
        rig.clock.advance_continuous_only(Duration::from_secs(1));
        svc.supervisor().scheduler_pass().await.unwrap();
        assert_eq!(
            grant_state(&svc, &data),
            GrantState::Expired,
            "expired at the budget end although the wall clock reads 30 s before the bound"
        );
        assert!(svc.operations().timegate().check().await.unwrap().wall() < at(3600));
        scan_events(&svc);
    }

    #[tokio::test]
    async fn scheduler_expires_at_the_same_bound_after_a_reboot_with_sync() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let svc = rig.service().await;
        let data = ensure(&svc, "req-rb", "work-rb", "1h").await;
        rig.clock.advance(10 * MINUTE);
        svc.supervisor().scheduler_pass().await.unwrap();
        drop(svc);
        // Reboot: new boot ID, continuous restarts at zero, wall above the mark and
        // reported synchronized.
        rig.clock.reboot(at(20 * 60));
        let svc = rig.service().await;
        let sup = svc.supervisor();
        assert_eq!(sup.time_guard_pass().await.unwrap(), TimeStatus::Safe);
        assert_eq!(
            sup.scheduler_pass().await.unwrap(),
            Some(at(3600)),
            "re-anchored in the new boot with the same persisted bound"
        );
        rig.clock.advance(40 * MINUTE - Duration::from_secs(1));
        sup.scheduler_pass().await.unwrap();
        assert_eq!(grant_state(&svc, &data), GrantState::Active);
        rig.clock.advance(Duration::from_secs(1));
        sup.scheduler_pass().await.unwrap();
        assert_eq!(grant_state(&svc, &data), GrantState::Expired);
        scan_events(&svc);
    }

    #[tokio::test]
    async fn supervisor_run_loop_expires_due_grants_on_its_own() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let fake = rig.fake(vec![FakeStep::Prepare(outcome())]);
        let mut options = rig.options(&fake);
        options.supervisor = heimdall_runtime::supervisor::SupervisorConfig {
            anchor_interval: Duration::from_millis(20),
            max_idle_sleep: Duration::from_millis(20),
            ..Default::default()
        };
        let shutdown = CancellationToken::new();
        let svc = Service::start_with(rig.paths(), Config::default(), options, shutdown.clone())
            .await
            .unwrap();
        let data = ensure(&svc, "req-loop", "work-loop", "1h").await;
        let store = svc.store().clone();
        let running = tokio::spawn(svc.run());
        let state = |store: &Arc<Store>| {
            store
                .transaction(|tx| tx.grant(&data.grant_id))
                .unwrap()
                .unwrap()
                .state
        };
        // Not due yet: the loop keeps it active.
        rig.clock.advance(HOUR - Duration::from_secs(1));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(state(&store), GrantState::Active);
        rig.clock.advance(Duration::from_secs(1));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while state(&store) != GrantState::Expired {
            assert!(
                tokio::time::Instant::now() < deadline,
                "loop never expired the grant"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(20), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    /// Review B04: a system sleep across a deadline is detected by the running
    /// loop within its resume-check bound, with production guard and idle
    /// intervals (60 s / 300 s) and **no application event**. The sleep is
    /// simulated with the virtual clock: wall and continuous time jump past the
    /// grant's bound while the process's monotonic timer barely moves (as after a
    /// resume on a platform whose timer excludes suspend). Without a bounded wait
    /// the loop would sleep until its next 60 s guard pass. Native suspend/resume
    /// evidence is an M04 item.
    #[tokio::test]
    async fn supervisor_detects_a_sleep_across_a_deadline_within_the_resume_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let fake = rig.fake(vec![FakeStep::Prepare(outcome())]);
        let mut options = rig.options(&fake);
        options.supervisor = heimdall_runtime::supervisor::SupervisorConfig {
            anchor_interval: Duration::from_secs(60),
            max_idle_sleep: Duration::from_secs(300),
            ..Default::default()
        };
        let shutdown = CancellationToken::new();
        let svc = Service::start_with(rig.paths(), Config::default(), options, shutdown.clone())
            .await
            .unwrap();
        let data = ensure(&svc, "req-sl", "work-sl", "1h").await;
        let store = svc.store().clone();
        let running = tokio::spawn(svc.run());
        let state = |store: &Arc<Store>| {
            store
                .transaction(|tx| tx.grant(&data.grant_id))
                .unwrap()
                .unwrap()
                .state
        };
        // The loop runs its start passes, then waits.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(state(&store), GrantState::Active);

        // The machine "sleeps" for an hour and a second, then resumes.
        rig.clock.advance(HOUR + Duration::from_secs(1));
        let resumed = std::time::Instant::now();
        // Bound: the resume-check interval (default 2 s, at most 5 s) plus
        // scheduling slack.
        let check = heimdall_runtime::supervisor::SupervisorConfig::default().resume_bound();
        assert!(check <= heimdall_runtime::supervisor::MAX_RESUME_CHECK_INTERVAL);
        let bound = check + Duration::from_secs(2);
        while state(&store) != GrantState::Expired {
            assert!(
                resumed.elapsed() < bound,
                "the sleep was not detected within {bound:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(20), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let page = store
            .transaction(|tx| {
                tx.stored_events_after(
                    &env_id(),
                    0,
                    &heimdall_contract::event::EventFilter::default(),
                    10_000,
                )
            })
            .unwrap();
        for e in &page.events {
            assert_no_canary(&serde_json::to_string(&e.event).unwrap());
        }
    }

    /// The resume-check interval is configurable but clamped to at most 5 s and
    /// at least 10 ms (never a tight loop); the default is 2 s.
    #[test]
    fn supervisor_resume_check_interval_is_bounded() {
        use heimdall_runtime::supervisor::{
            MAX_RESUME_CHECK_INTERVAL, MIN_RESUME_CHECK_INTERVAL, SupervisorConfig,
        };
        assert_eq!(MAX_RESUME_CHECK_INTERVAL, Duration::from_secs(5));
        let with = |d: Duration| SupervisorConfig {
            resume_check_interval: d,
            ..SupervisorConfig::default()
        };
        assert_eq!(
            SupervisorConfig::default().resume_bound(),
            Duration::from_secs(2)
        );
        assert_eq!(with(HOUR).resume_bound(), MAX_RESUME_CHECK_INTERVAL);
        assert_eq!(
            with(Duration::ZERO).resume_bound(),
            MIN_RESUME_CHECK_INTERVAL
        );
        assert_eq!(
            with(Duration::from_millis(250)).resume_bound(),
            Duration::from_millis(250)
        );
    }

    /// Store fault hook that fails every `BeforeCommit` while armed.
    struct FailWhileArmed(AtomicBool);

    impl FaultHook for FailWhileArmed {
        fn at(&self, point: FaultPoint) -> FaultAction {
            if point == FaultPoint::BeforeCommit && self.0.load(Ordering::SeqCst) {
                FaultAction::Fail
            } else {
                FaultAction::Continue
            }
        }
    }

    /// Review A05 integration: an event held back behind an unread gap (its
    /// catch-up read failed) reaches live subscribers once the store is readable
    /// again, without waiting for another commit. The running supervisor retries
    /// the held-back events on its bounded wake (`EventPublisher::retry_held`).
    #[tokio::test]
    async fn supervisor_delivers_held_back_events_without_a_new_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let fake = rig.fake(Vec::new());
        let mut options = rig.options(&fake);
        let faults = Arc::new(FailWhileArmed(AtomicBool::new(false)));
        options.store_faults = faults.clone();
        // No ordinary pass runs during the test window; only the bounded wake.
        options.supervisor = heimdall_runtime::supervisor::SupervisorConfig {
            anchor_interval: HOUR,
            max_idle_sleep: HOUR,
            resume_check_interval: Duration::from_millis(50),
            ..Default::default()
        };
        let shutdown = CancellationToken::new();
        let svc = Service::start_with(rig.paths(), Config::default(), options, shutdown.clone())
            .await
            .unwrap();
        let store = svc.store().clone();
        let publisher = svc.operations().events().clone();
        let running = tokio::spawn(svc.run());
        // The loop runs its start passes, then waits.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let mut live = publisher.live_receiver();
        let commit = |n: u32| {
            store
                .transaction(|tx| {
                    publisher.append_in(
                        tx,
                        heimdall_contract::event::EventType::ResourceChanged,
                        None,
                        None,
                        serde_json::json!({ "writer": n }),
                    )
                })
                .unwrap()
        };
        let e1 = commit(1);
        let e2 = commit(2);
        // e2 is announced first and its catch-up read (for e1) fails: held back.
        faults.0.store(true, Ordering::SeqCst);
        publisher.announce(e2.clone());
        faults.0.store(false, Ordering::SeqCst);
        assert!(
            live.try_recv().is_err(),
            "nothing is delivered past the unread gap"
        );
        // No further commit or announcement: the supervisor's retry delivers both.
        let mut got = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while got.len() < 2 {
            match tokio::time::timeout(Duration::from_millis(50), live.recv()).await {
                Ok(Ok(e)) => got.push(e.seq),
                Ok(Err(e)) => panic!("live stream closed or lagged: {e}"),
                Err(_) => assert!(
                    std::time::Instant::now() < deadline,
                    "held-back events were not delivered without a new commit"
                ),
            }
        }
        assert_eq!(got, vec![e1.seq, e2.seq], "delivered once each, in order");
        assert!(publisher.retry_held(), "nothing is held back any more");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(20), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    // -----------------------------------------------------------------------
    // Time guard
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn time_guard_refuses_a_rollback_and_ensure_is_time_uncertain() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let svc = rig.service().await;
        let sup = svc.supervisor();
        rig.clock.advance(MINUTE);
        assert_eq!(sup.time_guard_pass().await.unwrap(), TimeStatus::Safe);
        // Wall clock steps back 10 s (beyond the 5 s rollback tolerance).
        rig.clock.set_wall(at(60 - 10));
        let status = sup.time_guard_pass().await.unwrap();
        assert!(
            matches!(
                status,
                TimeStatus::Uncertain(TimeUncertainty::BelowHighWater { .. })
            ),
            "rollback refused: {status:?}"
        );
        let e = err(svc
            .operations()
            .ensure(&owner(), ensure_req("req-rl", "work-rl", Some("1h")))
            .await);
        assert_eq!(e.code, Code::TimeUncertain);
        assert_eq!(rig.ledger_entries(), 0, "nothing prepared while uncertain");
        scan_events(&svc);
    }

    #[tokio::test]
    async fn time_guard_refuses_an_unsynchronized_reboot_and_ensure_is_time_uncertain() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        drop(rig.service().await);
        rig.clock.reboot(at(3600));
        rig.sync.set(SyncStatus::Unknown);
        // Start-up is not refused (passive reads continue); activation is.
        let svc = rig.service().await;
        let sup = svc.supervisor();
        let status = sup.time_guard_pass().await.unwrap();
        assert!(
            matches!(
                status,
                TimeStatus::Uncertain(TimeUncertainty::Unsynchronized { .. })
            ),
            "unsynchronized reboot refused: {status:?}"
        );
        let e = err(svc
            .operations()
            .ensure(&owner(), ensure_req("req-us", "work-us", Some("1h")))
            .await);
        assert_eq!(e.code, Code::TimeUncertain);
        assert_eq!(rig.ledger_entries(), 0);
        // Synchronization returns: the same gate admits again.
        rig.sync.set(SyncStatus::Synchronized);
        assert_eq!(sup.time_guard_pass().await.unwrap(), TimeStatus::Safe);
        let ready = ensure(&svc, "req-us2", "work-us2", "1h").await;
        assert_eq!(ready.expires_at, at(2 * 3600));
        scan_events(&svc);
    }

    // -----------------------------------------------------------------------
    // Restart recovery (A17 local, in-process)
    // -----------------------------------------------------------------------

    /// Store fault hook (production `FaultHook`): fails the first `BeforeCommit`
    /// after the fake adapter applied an effect, so the `Confirmed` receipt never
    /// becomes durable and the operation rests on its `Attempted` receipt.
    struct FailCommitAfterEffect {
        ledger: PathBuf,
        armed: AtomicBool,
    }

    impl FaultHook for FailCommitAfterEffect {
        fn at(&self, point: FaultPoint) -> FaultAction {
            if point == FaultPoint::BeforeCommit
                && self.armed.load(Ordering::SeqCst)
                && FakeCredentialAdapter::ledger_entries(&self.ledger)
                    .map(|e| !e.is_empty())
                    .unwrap_or(false)
            {
                self.armed.store(false, Ordering::SeqCst);
                return FaultAction::Fail;
            }
            FaultAction::Continue
        }
    }

    #[tokio::test]
    async fn restart_recovery_reconciles_an_attempted_receipt_without_preparing_again() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let fake = rig.fake(vec![FakeStep::Prepare(outcome())]);
        let mut options = rig.options(&fake);
        options.store_faults = Arc::new(FailCommitAfterEffect {
            ledger: rig.ledger.clone(),
            armed: AtomicBool::new(true),
        });
        let svc = rig.start(options).await.unwrap();
        let e = err(svc
            .operations()
            .ensure(&owner(), ensure_req("req-at", "work-at", Some("1h")))
            .await);
        assert_eq!(e.code, Code::StateUnavailable);
        let op = e.operation_id.clone().unwrap();
        assert_eq!(rig.ledger_entries(), 1, "the effect happened once");
        let record = svc
            .store()
            .transaction(|tx| tx.operation(&op))
            .unwrap()
            .unwrap();
        assert_eq!(record.state, OperationState::Running);
        let receipts = svc
            .store()
            .transaction(|tx| tx.stage_receipts(&op))
            .unwrap();
        assert!(matches!(
            receipts.last().map(|r| &r.effect),
            Some(EffectReceipt::Attempted { .. })
        ));
        let env_before = svc.environment().clone();
        drop(svc);

        // Restart with a new adapter instance over the same durable ledger whose
        // script would fail any second `prepare`: recovery must reconcile instead.
        let fresh = rig.fake(vec![FakeStep::Fail(
            heimdall_app::ports::AdapterError::Unavailable("no second prepare".into()),
        )]);
        let svc = rig.start(rig.options(&fresh)).await.unwrap();
        let record = svc
            .store()
            .transaction(|tx| tx.operation(&op))
            .unwrap()
            .unwrap();
        assert_eq!(record.state, OperationState::Succeeded);
        assert_eq!(rig.ledger_entries(), 1, "reconciled, never re-prepared");
        assert_eq!(svc.environment(), &env_before);
        // The same-key retry replays the settled result.
        let replay = ok(svc
            .operations()
            .ensure(&owner(), ensure_req("req-at", "work-at", Some("1h")))
            .await);
        assert_eq!(replay.environment_id, env_before);
        assert_eq!(rig.ledger_entries(), 1);
        scan_events(&svc);
    }

    #[tokio::test]
    async fn restart_never_revives_a_paused_policy_or_changes_identity() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let svc = rig.service().await;
        let paused = ok(svc
            .operations()
            .policy(
                &owner(),
                PolicyAction::Pause {
                    policy_id: policy_id(),
                },
            )
            .await);
        assert_eq!(paused["paused"], true);
        drop(svc);
        let svc = rig.service().await;
        assert_eq!(svc.environment(), &env_id());
        let policy = svc
            .store()
            .transaction(|tx| tx.policy(&policy_id()))
            .unwrap()
            .unwrap();
        assert_ne!(
            policy.pause,
            PauseState::Active,
            "the pause survives restart"
        );
        let e = err(svc
            .operations()
            .ensure(&owner(), ensure_req("req-pp", "work-pp", Some("1h")))
            .await);
        assert_eq!(e.code, Code::PolicyPaused);
        assert_eq!(rig.ledger_entries(), 0);
        // Resuming is a widening action: a decision record, nothing executed.
        let r = err(svc
            .operations()
            .policy(
                &owner(),
                PolicyAction::Resume {
                    policy_id: policy_id(),
                },
            )
            .await);
        assert_eq!(r.code, Code::InteractionRequired);
        assert!(r.next.decision_ref.is_some());
        scan_events(&svc);
    }

    // -----------------------------------------------------------------------
    // Dispatcher: caller construction
    // -----------------------------------------------------------------------

    #[test]
    fn caller_is_built_from_the_session_only() {
        let session = SessionInfo {
            principal: PrincipalInfo::OsUserUnix { uid: 501 },
            interaction: InteractionMode::Interactive,
            attended: false,
        };
        let c = caller_for(&session, t0());
        assert_eq!(c.context.principal, PrincipalRef::UnixUser { uid: 501 });
        assert_eq!(c.context.role, ClientRole::Owner);
        assert!(!c.is_attended());
        assert!(c.may_attend());
        let attended = SessionInfo {
            attended: true,
            ..session.clone()
        };
        assert!(caller_for(&attended, t0()).is_attended());
        let windows = SessionInfo {
            principal: PrincipalInfo::OsUserWindows {
                sid: "S-1-5-21-1-2-3-1001".into(),
            },
            interaction: InteractionMode::NonInteractive,
            attended: false,
        };
        let w = caller_for(&windows, t0());
        assert_eq!(
            w.context.principal,
            PrincipalRef::WindowsUser {
                sid: "S-1-5-21-1-2-3-1001".into()
            }
        );
        assert!(!w.may_attend());
    }

    #[tokio::test]
    async fn dispatcher_rechecks_attendance_and_renders_application_results() {
        use heimdall_contract::request::{
            ConfirmTimeRequest, DecideRequest, InspectRequest, InspectSubject, Request, Verdict,
        };
        use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};

        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let svc = rig.service().await;
        let stop = CancellationToken::new();
        let relay = EventRelay::spawn(svc.operations(), stop.clone());
        let d = OperationsDispatcher::new(svc.operations().clone(), relay, rig.clock.clone());
        let unattended = SessionInfo {
            principal: PrincipalInfo::OsUserUnix { uid: 501 },
            interaction: InteractionMode::Interactive,
            attended: false,
        };
        // Even if a session forwarded them, attended-only requests are refused here.
        for request in [
            Request::Decide(DecideRequest {
                decision_id: heimdall_contract::ids::DecisionId::from_random_bytes([4; 16]),
                verdict: Verdict::Approve,
            }),
            Request::ConfirmTime(ConfirmTimeRequest {
                observed_wall: t0(),
            }),
        ] {
            let env = d.handle(&unattended, request).await;
            assert_no_canary(&serde_json::to_string(&env).unwrap());
            assert_eq!(env.code, Code::InteractionRequired);
            assert_eq!(env.data["error"]["code"], "INTERACTION_REQUIRED");
        }
        // Reads and effects render the application's envelope unchanged.
        let caps = d
            .handle(
                &unattended,
                Request::Inspect(InspectRequest {
                    subject: InspectSubject::Capabilities,
                    preview: None,
                }),
            )
            .await;
        assert_eq!(caps.code, Code::Ok);
        assert!(caps.data["capabilities"].is_array());
        // Discovery (`inspect capabilities`, §2.4) lists exactly what the hello
        // offers, including `service-control/1` (ADR-0006 §13.6 item 8).
        let discovered: std::collections::BTreeSet<String> = caps.data["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(discovered, heimdall_ipc::session::server_capabilities());
        let ready = d
            .handle(
                &unattended,
                Request::Ensure(ensure_req("req-d", "work-d", Some("1h"))),
            )
            .await;
        assert_no_canary(&serde_json::to_string(&ready).unwrap());
        assert_eq!(ready.code, Code::AccessReady);
        assert_eq!(ready.data["environment_id"], env_id().as_str());
        // An attended session reaches the application, which answers on its own
        // terms (an unknown decision is not found, never executed).
        let attended = SessionInfo {
            attended: true,
            ..unattended.clone()
        };
        let unknown = d
            .handle(
                &attended,
                Request::Decide(DecideRequest {
                    decision_id: heimdall_contract::ids::DecisionId::from_random_bytes([4; 16]),
                    verdict: Verdict::Approve,
                }),
            )
            .await;
        assert_ne!(unknown.code, Code::InteractionRequired);
        assert_ne!(unknown.code, Code::Ok);
        stop.cancel();
    }

    // -----------------------------------------------------------------------
    // Full control-socket round trip against a real service
    // -----------------------------------------------------------------------

    async fn client(
        path: &Path,
        mode: InteractionMode,
    ) -> heimdall_ipc::session::ControlClient<ControlStream> {
        control_client(path, mode).await
    }

    fn scan_envelope(env: &Envelope<serde_json::Value>) {
        assert_no_canary(&serde_json::to_string(env).unwrap());
    }

    /// Events on any subscription of `c` until none arrives for 500 ms; each is
    /// scanned for canaries and must carry a cursor.
    async fn drain_events(
        c: &mut heimdall_ipc::session::ControlClient<ControlStream>,
    ) -> Vec<heimdall_contract::event::Event> {
        let mut seen = Vec::new();
        while let Ok(next) = tokio::time::timeout(Duration::from_millis(500), c.next_event()).await
        {
            let (_, event) = next.unwrap();
            assert_no_canary(&serde_json::to_string(&event).unwrap());
            assert!(
                !event.cursor.0.is_empty(),
                "delivered events carry a cursor"
            );
            seen.push(event);
        }
        seen
    }

    /// Runs on Unix (socket) and Windows (named pipe; ADR-0006 §13.6 item 8):
    /// hello, ensure with the fake adapter, subscribe, events, attendance, and the
    /// end of the session at shutdown.
    #[tokio::test]
    async fn control_socket_round_trip_against_a_real_service() {
        use heimdall_contract::event::EventFilter;
        use heimdall_contract::request::{DecideRequest, Request, Verdict};
        use heimdall_ipc::session::SubscribeOutcome;

        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let fake = rig.fake(vec![FakeStep::Prepare(outcome())]);
        let shutdown = CancellationToken::new();
        let svc = Service::start_with(
            rig.paths(),
            Config::default(),
            rig.options(&fake),
            shutdown.clone(),
        )
        .await
        .unwrap();
        let control = svc.endpoints().control.clone();
        let signing = svc.endpoints().signing.clone();
        assert_ne!(control, signing);
        let running = tokio::spawn(svc.run());

        // Hello: the server reports this runtime's environment and our principal.
        let mut c = client(&control, InteractionMode::NonInteractive).await;
        assert_eq!(c.server().environment_id, env_id());
        #[cfg(unix)]
        assert_eq!(
            c.server().principal,
            PrincipalInfo::OsUserUnix {
                uid: heimdall_ipc::unix::current_uid()
            }
        );
        #[cfg(windows)]
        assert_eq!(
            c.server().principal,
            PrincipalInfo::OsUserWindows {
                sid: heimdall_ipc::windows::current_user_sid().unwrap()
            }
        );

        // Subscribe without a cursor: a consistent snapshot and a boundary cursor.
        let SubscribeOutcome::Subscribed {
            subscription,
            cursor: boundary,
            snapshot,
        } = c.subscribe(EventFilter::default(), None).await.unwrap()
        else {
            panic!("subscription refused");
        };
        assert!(snapshot.is_some());

        // Ensure with the fake adapter.
        let env = c
            .request(Request::Ensure(ensure_req("req-rt", "work-rt", Some("1h"))))
            .await
            .unwrap();
        scan_envelope(&env);
        assert_eq!(env.code, Code::AccessReady);
        assert_eq!(env.state, OperationState::Succeeded);
        let op = env.operation_id.clone().unwrap();
        let data: EnsureData = serde_json::from_value(env.data.clone()).unwrap();
        assert_eq!(data.environment_id, env_id());
        assert_eq!(rig.ledger_entries(), 1);

        // Live events for that operation arrive on the subscription.
        let live = drain_events(&mut c).await;
        assert!(live.iter().any(|e| e.operation_id.as_ref() == Some(&op)));
        assert!(live.iter().all(|e| e.environment_id == env_id()));
        c.unsubscribe(subscription).await.unwrap();

        // Resume from the earlier boundary: the backlog replays the same events
        // (no snapshot), in order.
        let SubscribeOutcome::Subscribed { snapshot, .. } = c
            .subscribe(EventFilter::default(), Some(boundary))
            .await
            .unwrap()
        else {
            panic!("resubscription refused");
        };
        assert!(
            snapshot.is_none(),
            "a usable cursor resumes from the backlog"
        );
        let replayed = drain_events(&mut c).await;
        // Same events in the same order: live delivery is in store `seq` order
        // (gap G06; `EventPublisher::announce`), and so is the backlog. Each live
        // event carries the cursor of its own position.
        let ids = |v: &[heimdall_contract::event::Event]| {
            v.iter()
                .map(|e| (e.event_id.clone(), e.event_type, e.operation_id.clone()))
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(&replayed), ids(&live));
        let live_seqs: Vec<u64> = live
            .iter()
            .map(|e| heimdall_app::events::cursor::decode(&e.cursor).unwrap().seq)
            .collect();
        assert!(
            live_seqs.windows(2).all(|w| w[0] < w[1]),
            "live delivery in store order: {live_seqs:?}"
        );
        let seqs: Vec<u64> = replayed
            .iter()
            .map(|e| heimdall_app::events::cursor::decode(&e.cursor).unwrap().seq)
            .collect();
        assert!(
            seqs.windows(2).all(|w| w[0] < w[1]),
            "backlog in store order"
        );

        // Attended-only requests are refused on an unattended session.
        let refused = c
            .request(Request::Decide(DecideRequest {
                decision_id: heimdall_contract::ids::DecisionId::from_random_bytes([3; 16]),
                verdict: Verdict::Approve,
            }))
            .await
            .unwrap();
        scan_envelope(&refused);
        assert_eq!(refused.code, Code::InteractionRequired);
        // A widening policy action is dispatched and answered with a decision
        // record (unattended: INTERACTION_REQUIRED + decision_ref).
        let pause = c
            .request(Request::Policy(PolicyAction::Pause {
                policy_id: policy_id(),
            }))
            .await
            .unwrap();
        assert_eq!(pause.code, Code::Ok);
        let resume = c
            .request(Request::Policy(PolicyAction::Resume {
                policy_id: policy_id(),
            }))
            .await
            .unwrap();
        scan_envelope(&resume);
        assert_eq!(resume.code, Code::InteractionRequired);
        let unattended_ref = resume.next.as_ref().and_then(|n| n.decision_ref.clone());
        assert!(unattended_ref.is_some());

        // Attended interactive session: still a decision record, never executed on
        // dispatch (APPROVAL_REQUIRED + decision_ref).
        let mut a = client(&control, InteractionMode::Interactive).await;
        let attended = a.attend().await.unwrap();
        assert_eq!(attended.code, Code::Ok);
        let resume = a
            .request(Request::Policy(PolicyAction::Resume {
                policy_id: policy_id(),
            }))
            .await
            .unwrap();
        scan_envelope(&resume);
        assert_eq!(resume.code, Code::ApprovalRequired);
        assert!(
            resume
                .next
                .as_ref()
                .and_then(|n| n.decision_ref.clone())
                .is_some()
        );
        let still = c
            .request(Request::Ensure(ensure_req(
                "req-rt2",
                "work-rt2",
                Some("1h"),
            )))
            .await
            .unwrap();
        scan_envelope(&still);
        assert_eq!(
            still.code,
            Code::PolicyPaused,
            "resume not executed on dispatch"
        );

        // Shutdown: sessions get Goodbye(SERVICE_UNAVAILABLE), the advertisement
        // and the sockets disappear, and the lock is released.
        shutdown.cancel();
        let refusal = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match c.next_event().await {
                    // Events still queued on the open subscription come first.
                    Ok((_, event)) => assert_no_canary(&serde_json::to_string(&event).unwrap()),
                    Err(e) => break e,
                }
            }
        })
        .await
        .expect("goodbye within the timeout");
        match heimdall_ipc::session::server_refusal(&refusal) {
            Some(heimdall_ipc::session::ServerRefusal::Goodbye { code, .. }) => {
                assert_eq!(*code, Code::ServiceUnavailable);
            }
            other => panic!("expected a goodbye, got {other:?}"),
        }
        tokio::time::timeout(Duration::from_secs(20), running)
            .await
            .expect("run returns after shutdown")
            .unwrap()
            .unwrap();
        assert!(!rig.paths().runtime_dir.join(INSTANCE_FILE).exists());
        assert_endpoints_gone(&heimdall_ipc::EndpointPaths {
            control,
            signing,
            issuer: PathBuf::new(),
        })
        .await;
        let again = rig.service().await;
        assert_eq!(again.environment(), &env_id());
    }

    // -----------------------------------------------------------------------
    // Launcher: concurrent clients start exactly one child
    // -----------------------------------------------------------------------

    /// Environment variable that turns [`launcher_child_service`] into a service
    /// host for the given `HEIMDALL_HOME` layout.
    const CHILD_ENV: &str = "HEIMDALL_U8B_CHILD_HOME";
    const CHILD_TEST: &str = "u8b::launcher_child_service";

    /// Child-process entry, not a test of its own: re-executed by
    /// `launcher_eight_concurrent_clients_start_exactly_one_child` with
    /// `CHILD_ENV` set, it runs the production service sources (system clock;
    /// Windows pipes with the test prefix) until a `stop` file appears in the home
    /// (or 60 s pass).
    #[test]
    #[ignore = "child-process entry for the launcher test; runs only when re-executed by it"]
    fn launcher_child_service() {
        let Some(home) = std::env::var_os(CHILD_ENV) else {
            return;
        };
        let home = PathBuf::from(home);
        let rt = Service::runtime().unwrap();
        rt.block_on(async move {
            let shutdown = CancellationToken::new();
            let mut options = ServiceOptions::production().unwrap();
            options.endpoint_prefix = TEST_PIPE_PREFIX.to_owned();
            let svc = Service::start_with(
                Paths::under(&home),
                Config::default(),
                options,
                shutdown.clone(),
            )
            .await
            .unwrap();
            let stop = home.join("stop");
            let token = shutdown.clone();
            tokio::spawn(async move {
                let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
                while !stop.exists() && tokio::time::Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                token.cancel();
            });
            svc.run().await.unwrap();
        });
    }

    /// Runs on Unix and Windows (ADR-0006 §13.6 item 8).
    #[test]
    fn launcher_eight_concurrent_clients_start_exactly_one_child() {
        use std::process::{Child, Command, Stdio};

        let tmp = tempfile::tempdir().unwrap();
        let home = home(&tmp);
        let paths = Paths::under(&home);
        paths.ensure().unwrap();
        let run_dir = paths.runtime_dir.clone();
        let exe = std::env::current_exe().unwrap();
        let children: Arc<Mutex<Vec<Child>>> = Arc::new(Mutex::new(Vec::new()));
        let spawns = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let config = LauncherConfig {
            start_timeout: Duration::from_secs(60),
            initial_poll: Duration::from_millis(10),
        };

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (children, spawns, barrier) =
                    (children.clone(), spawns.clone(), barrier.clone());
                let (exe, home, run_dir) = (exe.clone(), home.clone(), run_dir.clone());
                std::thread::spawn(move || {
                    let spawn = move || {
                        spawns.fetch_add(1, Ordering::SeqCst);
                        let child = Command::new(&exe)
                            .args([CHILD_TEST, "--exact", "--ignored", "--test-threads=1"])
                            .env(CHILD_ENV, &home)
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .spawn()?;
                        children.lock().unwrap().push(child);
                        Ok(())
                    };
                    barrier.wait();
                    Service::runtime()
                        .unwrap()
                        .block_on(ensure_running_with(&run_dir, true, config, &spawn))
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let stop_child = |children: &Arc<Mutex<Vec<Child>>>| {
            std::fs::write(home.join("stop"), b"").unwrap();
            let mut list = children.lock().unwrap();
            let mut statuses = Vec::new();
            for child in list.iter_mut() {
                let deadline = std::time::Instant::now() + Duration::from_secs(30);
                let status = loop {
                    if let Some(s) = child.try_wait().unwrap() {
                        break Some(s);
                    }
                    if std::time::Instant::now() >= deadline {
                        // Only the exact child this test started.
                        let _ = child.kill();
                        let _ = child.wait();
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                };
                statuses.push(status);
            }
            statuses
        };

        let started = results
            .iter()
            .filter(|r| matches!(r, Ok(Started::StartedNow)))
            .count();
        let already = results
            .iter()
            .filter(|r| matches!(r, Ok(Started::AlreadyRunning)))
            .count();
        let spawned = spawns.load(Ordering::SeqCst);
        let child_pid = children.lock().unwrap().first().map(Child::id);
        let advertised = InstanceInfo::read_valid(&run_dir).unwrap();
        // A ninth client afterwards finds the running instance without spawning.
        let ninth = Service::runtime().unwrap().block_on(ensure_running_with(
            &run_dir,
            true,
            config,
            &|| -> std::io::Result<()> { panic!("must not spawn") },
        ));
        // The child serves the control endpoint.
        let control = advertised
            .as_ref()
            .map(|i| PathBuf::from(&i.control_endpoint))
            .unwrap_or_default();
        #[cfg(unix)]
        assert_eq!(control, run_dir.join("control.sock"));
        let hello_env = Service::runtime().unwrap().block_on(async {
            let c = client(&control, InteractionMode::NonInteractive).await;
            c.server().environment_id.clone()
        });
        let statuses = stop_child(&children);

        assert_eq!(spawned, 1, "exactly one child spawned");
        assert_eq!(started, 1, "{results:?}");
        assert_eq!(already, 7, "{results:?}");
        assert_eq!(advertised.as_ref().map(|i| i.pid), child_pid);
        assert!(matches!(ninth, Ok(Started::AlreadyRunning)));
        let recorded = Store::open(&paths.state_dir.join(STATE_DB_FILE), Arc::new(NoFaults))
            .unwrap()
            .transaction(|tx| tx.self_environment())
            .unwrap();
        assert_eq!(recorded, Some(hello_env));
        assert_eq!(statuses.len(), 1);
        assert!(
            statuses[0].is_some_and(|s| s.success()),
            "child exits cleanly on stop: {statuses:?}"
        );
        assert!(!run_dir.join(INSTANCE_FILE).exists());
        #[cfg(unix)]
        assert!(!run_dir.join("control.sock").exists());
    }

    // -----------------------------------------------------------------------
    // ADR-0006 §13.6 item 4: supervisor-owned retries are bounded and jittered
    // -----------------------------------------------------------------------

    /// A cleaner whose dependency is always unavailable; records the continuous
    /// clock reading of every delete call.
    struct UnavailableCleaner {
        clock: Arc<VirtualClock>,
        calls: std::sync::Mutex<Vec<Duration>>,
    }

    impl heimdall_app::ports::ResourceCleaner for UnavailableCleaner {
        fn delete<'life0, 'life1, 'async_trait>(
            &'life0 self,
            _resource: &'life1 heimdall_domain::resource::ManagedResource,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(), heimdall_app::ports::AdapterError>>
                    + Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            use heimdall_domain::time::Clock as _;
            self.calls.lock().unwrap().push(self.clock.continuous());
            Box::pin(async {
                Err(heimdall_app::ports::AdapterError::Unavailable(
                    "fixture dependency down".into(),
                ))
            })
        }
    }

    /// Deterministic jitter: cycles through fixed units in `[0, 1)`.
    struct CycleJitter {
        units: Vec<f64>,
        next: std::sync::atomic::AtomicUsize,
    }

    impl heimdall_runtime::supervisor::Jitter for CycleJitter {
        fn unit(&self) -> f64 {
            let i = self.next.fetch_add(1, Ordering::SeqCst);
            self.units[i % self.units.len()]
        }
    }

    fn ending_resource() -> heimdall_domain::resource::ManagedResource {
        use heimdall_domain::resource::{
            ManagedResource, OwnerRef, ResourceGeneration, ResourceKind, ResourceState,
        };
        ManagedResource {
            id: heimdall_contract::ids::ResourceId::from_random_bytes([9; 16]),
            kind: ResourceKind::Endpoint,
            owner: OwnerRef::Runtime,
            generation: ResourceGeneration(1),
            desired: ResourceState::Absent,
            observed: ResourceState::Present,
            last_operation: None,
            locator: "fixture-endpoint".into(),
            updated_at: t0(),
        }
    }

    /// The single cleanup executor retries an unavailable dependency with the
    /// bounded backoff **jittered** by the injected source: each delay is
    /// `delay(n) * (0.5 + 0.5 * unit)`, attempts stop at `max_attempts` (8), then
    /// the stable code `SERVICE_UNAVAILABLE` is reported once. With the units
    /// `0.0, 1.0, 0.5, ...` the schedule is exactly predictable (deterministic in
    /// tests), and it differs from the unjittered one.
    #[tokio::test]
    async fn cleanup_retries_use_bounded_backoff_with_injected_jitter() {
        use heimdall_app::reconcile::{Backoff, NoCleanupHook};
        use heimdall_domain::time::Clock as _;
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let svc = rig.service().await;
        let r = ending_resource();
        svc.store()
            .transaction(|tx| tx.upsert_resource(&r, None))
            .unwrap();
        let cleaner = Arc::new(UnavailableCleaner {
            clock: rig.clock.clone(),
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let units = vec![0.0, 1.0, 0.5];
        let sup = svc
            .supervisor()
            .with_cleaner(cleaner.clone(), Arc::new(NoCleanupHook), Backoff::default())
            .with_jitter(Arc::new(CycleJitter {
                units: units.clone(),
                next: std::sync::atomic::AtomicUsize::new(0),
            }));
        let start = rig.clock.continuous();
        let step = Duration::from_millis(125);
        let mut scheduled = Vec::new();
        let mut failed = Vec::new();
        for _ in 0..(8 * 70) {
            let report = sup.cleanup_pass().await.unwrap();
            scheduled.extend(report.retry_scheduled.iter().map(|(_, n, d)| (*n, *d)));
            failed.extend(report.failed);
            rig.clock.advance(step);
        }
        let backoff = Backoff::default();
        let expected_delays: Vec<(u32, Duration)> = (1..backoff.max_attempts)
            .map(|n| {
                let u = units[(n as usize - 1) % units.len()];
                (n, backoff.jittered(n, u))
            })
            .collect();
        assert_eq!(scheduled, expected_delays, "jittered, bounded delays");
        let mut at = Duration::ZERO;
        let mut expected_offsets = vec![Duration::ZERO];
        for (_, d) in &expected_delays {
            at += *d;
            expected_offsets.push(at);
        }
        let offsets: Vec<Duration> = cleaner
            .calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.saturating_sub(start))
            .collect();
        assert_eq!(offsets, expected_offsets);
        assert_eq!(offsets.len(), 8, "attempts capped at max_attempts");
        // Not the unjittered schedule.
        let plain: Vec<Duration> = (1..8).map(|n| backoff.delay(n)).collect();
        assert_ne!(
            expected_delays.iter().map(|(_, d)| *d).collect::<Vec<_>>(),
            plain
        );
        assert_eq!(failed, vec![(r.id.clone(), Code::ServiceUnavailable)]);
        // After the cap nothing retries, whatever the clock does.
        rig.clock.advance(HOUR);
        let after = sup.cleanup_pass().await.unwrap();
        assert!(after.retry_scheduled.is_empty() && after.failed.is_empty());
        assert_eq!(cleaner.calls.lock().unwrap().len(), 8);
        scan_events(&svc);
    }

    /// Review B02: a retry recorded for generation N must not outlive N's cleanup
    /// candidacy. Generation N fails transiently (retry scheduled); before the
    /// retry is due the resource is replaced by an already-reconciled N+1 (not a
    /// cleanup candidate). Once N's old due time has passed, a pass must report no
    /// pending wake (a stale entry would report `Some(0)` forever: a zero-delay
    /// polling loop) and must not call the cleaner. The same holds when N itself
    /// becomes reconciled, and when the record disappears.
    #[tokio::test]
    async fn cleanup_retries_are_pruned_when_the_resource_is_replaced_or_reconciled() {
        use heimdall_app::reconcile::{Backoff, NoCleanupHook};
        use heimdall_domain::resource::{ResourceGeneration, ResourceState};
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let svc = rig.service().await;
        let cleaner = Arc::new(UnavailableCleaner {
            clock: rig.clock.clone(),
            calls: std::sync::Mutex::new(Vec::new()),
        });
        let sup = svc
            .supervisor()
            .with_cleaner(cleaner.clone(), Arc::new(NoCleanupHook), Backoff::default())
            .with_jitter(Arc::new(heimdall_runtime::supervisor::FixedJitter(1.0)));

        // Three resources, one per way of leaving the candidate set.
        let mk = |byte: u8| heimdall_domain::resource::ManagedResource {
            id: heimdall_contract::ids::ResourceId::from_random_bytes([byte; 16]),
            ..ending_resource()
        };
        let (replaced, reconciled, removed, repurposed) = (mk(21), mk(22), mk(23), mk(24));
        for r in [&replaced, &reconciled, &removed, &repurposed] {
            svc.store()
                .transaction(|tx| tx.upsert_resource(r, None))
                .unwrap();
        }
        let first = sup.cleanup_pass().await.unwrap();
        assert_eq!(first.retry_scheduled.len(), 4, "{first:?}");
        let due = first.next_due_in.expect("a retry is scheduled");
        assert!(due > Duration::ZERO);
        assert_eq!(cleaner.calls.lock().unwrap().len(), 4);

        // Between attempts: N+1 replaces N, already reconciled (present/present);
        // the second reaches its desired state; the third record is gone (the
        // store has no delete, so it leaves the candidate set as reconciled too);
        // the fourth stays out of sync at the same generation but is now wanted
        // present (an `Ensure`, not a cleanup: no cleanup retry may survive).
        let next_gen = heimdall_domain::resource::ManagedResource {
            generation: ResourceGeneration(2),
            desired: ResourceState::Present,
            observed: ResourceState::Present,
            ..replaced.clone()
        };
        let settled = heimdall_domain::resource::ManagedResource {
            observed: ResourceState::Absent,
            ..reconciled.clone()
        };
        let gone = heimdall_domain::resource::ManagedResource {
            observed: ResourceState::Absent,
            ..removed.clone()
        };
        let wanted = heimdall_domain::resource::ManagedResource {
            desired: ResourceState::Present,
            observed: ResourceState::Absent,
            ..repurposed.clone()
        };
        svc.store()
            .transaction(|tx| {
                tx.upsert_resource(&next_gen, Some(ResourceGeneration(1)))?;
                tx.upsert_resource(&settled, Some(ResourceGeneration(1)))?;
                tx.upsert_resource(&gone, Some(ResourceGeneration(1)))?;
                tx.upsert_resource(&wanted, Some(ResourceGeneration(1)))
            })
            .unwrap();

        // Well past the old due time: nothing is pending, so no wake at all.
        rig.clock.advance(due + HOUR);
        for _ in 0..3 {
            let report = sup.cleanup_pass().await.unwrap();
            assert_eq!(
                report.next_due_in, None,
                "no stale zero-delay wake: {report:?}"
            );
            assert!(report.retry_scheduled.is_empty() && report.failed.is_empty());
        }
        assert_eq!(
            cleaner.calls.lock().unwrap().len(),
            4,
            "no further delete for a generation that is no longer a candidate"
        );
        scan_events(&svc);
    }

    /// Counts `prepare` calls in front of the fake adapter.
    struct CountingAdapter {
        inner: Arc<FakeCredentialAdapter>,
        prepares: std::sync::atomic::AtomicUsize,
    }

    type AdapterFut<'a, T> = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<T, heimdall_app::ports::AdapterError>>
                + Send
                + 'a,
        >,
    >;

    impl CredentialAdapter for CountingAdapter {
        fn descriptor(&self) -> &AdapterDescriptor {
            self.inner.descriptor()
        }
        // ADR-0007 §12.26 item 2: no default bodies; this test adapter reads no
        // source and its bounded call is its own `prepare`.
        fn read_sources(
            &self,
            _pairs: &[heimdall_app::ports::PreparePair],
        ) -> heimdall_app::ports::IntegrationSnapshot {
            heimdall_app::ports::IntegrationSnapshot::default()
        }
        fn prepare_from<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            req: heimdall_app::ports::PrepareRequest<'life1>,
            _sources: &'life2 heimdall_app::ports::IntegrationSnapshot,
        ) -> AdapterFut<'async_trait, PrepareOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            self.prepare(req)
        }
        fn prepare<'life0, 'life1, 'async_trait>(
            &'life0 self,
            req: heimdall_app::ports::PrepareRequest<'life1>,
        ) -> AdapterFut<'async_trait, PrepareOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.prepares.fetch_add(1, Ordering::SeqCst);
            self.inner.prepare(req)
        }
        fn renew<'life0, 'life1, 'async_trait>(
            &'life0 self,
            req: heimdall_app::ports::PrepareRequest<'life1>,
        ) -> AdapterFut<'async_trait, PrepareOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.renew(req)
        }
        fn reconcile<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            grant: &'life1 heimdall_contract::ids::GrantId,
            effect_token: &'life2 str,
        ) -> AdapterFut<'async_trait, heimdall_app::ports::ReconcileOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.reconcile(grant, effect_token)
        }
        fn revoke<'life0, 'life1, 'async_trait>(
            &'life0 self,
            grant: &'life1 heimdall_contract::ids::GrantId,
            now: Timestamp,
        ) -> AdapterFut<'async_trait, heimdall_app::ports::RevokeOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.revoke(grant, now)
        }
    }

    /// ADR-0006 §13.6 item 4 (verify): a caller's operation whose `prepare`
    /// reports `Unavailable` is answered **once** with `SERVICE_UNAVAILABLE`
    /// (exit 5) and is not retried automatically: neither the running service's
    /// supervisor loop (scheduler, time guard, cleanup executor, each at a short
    /// interval while the virtual clock advances) nor a restart re-drives it; a
    /// same-key retry replays the recorded failure without calling the adapter.
    /// (In-process restart, labelled as such.)
    #[tokio::test]
    async fn unavailable_prepare_is_answered_once_and_never_retried_by_the_supervisor_or_a_restart()
    {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let counting = Arc::new(CountingAdapter {
            inner: rig.fake(vec![FakeStep::Fail(
                heimdall_app::ports::AdapterError::Unavailable(format!("dependency {}", canary())),
            )]),
            prepares: std::sync::atomic::AtomicUsize::new(0),
        });
        let options = || {
            let mut o = test_options(rig.clock.clone(), rig.sync.clone());
            o.adapters = vec![counting.clone() as Arc<dyn CredentialAdapter>];
            o.supervisor = heimdall_runtime::supervisor::SupervisorConfig {
                anchor_interval: Duration::from_millis(20),
                max_idle_sleep: Duration::from_millis(20),
                ..heimdall_runtime::supervisor::SupervisorConfig::default()
            };
            o
        };
        let shutdown = CancellationToken::new();
        let svc = Service::start_with(rig.paths(), Config::default(), options(), shutdown.clone())
            .await
            .unwrap();
        let e = err(svc
            .operations()
            .ensure(&owner(), ensure_req("req-un", "work-un", Some("1h")))
            .await);
        assert_eq!(e.code, Code::ServiceUnavailable);
        assert_eq!(e.code.exit_code(), heimdall_contract::ExitCode::Unavailable);
        assert_eq!(counting.prepares.load(Ordering::SeqCst), 1);
        let op = e
            .operation_id
            .clone()
            .expect("the failed operation is recorded");

        // The real supervisor loop runs for a while; the clock moves on.
        let running = tokio::spawn(svc.run());
        for _ in 0..25 {
            rig.clock.advance(MINUTE);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        shutdown.cancel();
        running.await.unwrap().unwrap();
        assert_eq!(
            counting.prepares.load(Ordering::SeqCst),
            1,
            "no supervisor retry of a caller's operation"
        );

        // In-process restart: restart recovery does not prepare again either.
        let again = Service::start_with(
            rig.paths(),
            Config::default(),
            options(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let sup = again.supervisor();
        sup.scheduler_pass().await.unwrap();
        sup.time_guard_pass().await.unwrap();
        assert_eq!(
            counting.prepares.load(Ordering::SeqCst),
            1,
            "no restart retry"
        );
        let state = again
            .store()
            .transaction(|tx| tx.operation(&op))
            .unwrap()
            .unwrap()
            .state;
        assert_eq!(state, OperationState::Failed);
        // The caller retries with the same key: the recorded answer, no new call.
        let replay = err(again
            .operations()
            .ensure(&owner(), ensure_req("req-un", "work-un", Some("1h")))
            .await);
        assert_eq!(replay.code, Code::ServiceUnavailable);
        assert_eq!(replay.operation_id.as_ref(), Some(&op));
        assert_eq!(counting.prepares.load(Ordering::SeqCst), 1);
        assert_eq!(rig.ledger_entries(), 0, "no effect");
        let decisions = again
            .store()
            .transaction(|tx| tx.pending_decisions())
            .unwrap();
        assert!(
            decisions.is_empty(),
            "an unavailable dependency never prompts"
        );
        scan_events(&again);
    }

    // -----------------------------------------------------------------------
    // ADR-0006 §13.6 item 8: Request::Shutdown (service-control/1)
    // -----------------------------------------------------------------------

    #[cfg(unix)]
    type ControlStream = tokio::net::UnixStream;
    #[cfg(windows)]
    type ControlStream = tokio::net::windows::named_pipe::NamedPipeClient;

    /// Connect to a running service's control endpoint the production way for the
    /// platform (Unix: private socket + peer check; Windows: named pipe with the
    /// server-owner check) and perform the hello.
    async fn control_client(
        endpoint: &Path,
        mode: InteractionMode,
    ) -> heimdall_ipc::session::ControlClient<ControlStream> {
        #[cfg(unix)]
        let stream = heimdall_ipc::unix::connect(endpoint).await.unwrap();
        #[cfg(windows)]
        let stream = heimdall_ipc::windows::connect_with_owner(
            endpoint,
            heimdall_ipc::windows::ServerOwner::CurrentUser,
        )
        .await
        .unwrap();
        heimdall_ipc::session::ControlClient::handshake(
            stream,
            heimdall_contract::ipc::PeerInfo {
                name: "r136-test".into(),
                version: "0".into(),
            },
            [heimdall_contract::ipc::capability::OPERATIONS_V1.to_owned()]
                .into_iter()
                .collect(),
            mode,
        )
        .await
        .unwrap()
    }

    fn shutdown_request() -> heimdall_contract::request::Request {
        heimdall_contract::request::Request::Shutdown(
            heimdall_contract::request::ShutdownRequest {},
        )
    }

    /// Read until the session ends; the end must be `Goodbye(SERVICE_UNAVAILABLE)`.
    async fn expect_goodbye(c: &mut heimdall_ipc::session::ControlClient<ControlStream>) {
        let end = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                match c.next_event().await {
                    Ok((_, event)) => assert_no_canary(&serde_json::to_string(&event).unwrap()),
                    Err(e) => break e,
                }
            }
        })
        .await
        .expect("goodbye within the timeout");
        match heimdall_ipc::session::server_refusal(&end) {
            Some(heimdall_ipc::session::ServerRefusal::Goodbye { code, .. }) => {
                assert_eq!(*code, Code::ServiceUnavailable);
            }
            other => panic!("expected a goodbye, got {other:?}"),
        }
    }

    /// Shutdown from the owner over the control endpoint, on an unattended
    /// non-interactive session: `OK {"stopping": true}` first, then the session's
    /// goodbye; `run` returns `Ok` (the CLI exits 0), the advertisement and both
    /// endpoints are gone, and the lock is free (a new instance starts with the
    /// same identity).
    #[tokio::test]
    async fn shutdown_from_the_owner_drains_and_removes_the_advertisement_and_endpoints() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let fake = rig.fake(vec![FakeStep::Prepare(outcome())]);
        let svc = Service::start_with(
            rig.paths(),
            Config::default(),
            rig.options(&fake),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let endpoints = svc.endpoints().clone();
        let running = tokio::spawn(svc.run());

        let mut c = control_client(&endpoints.control, InteractionMode::NonInteractive).await;
        assert!(
            c.server()
                .capabilities
                .contains(heimdall_contract::ipc::capability::SERVICE_CONTROL_V1)
        );
        let ready = c
            .request(heimdall_contract::request::Request::Ensure(ensure_req(
                "req-sd",
                "work-sd",
                Some("1h"),
            )))
            .await
            .unwrap();
        assert_eq!(ready.code, Code::AccessReady);
        let env = c.request(shutdown_request()).await.unwrap();
        assert_no_canary(&serde_json::to_string(&env).unwrap());
        assert_eq!(env.code, Code::Ok, "{env:?}");
        assert_eq!(env.data["stopping"], true);
        assert_eq!(env.data["already_stopping"], false);
        assert!(env.operation_id.is_none(), "not an operation");
        expect_goodbye(&mut c).await;

        tokio::time::timeout(Duration::from_secs(30), running)
            .await
            .expect("run returns after a Shutdown request")
            .unwrap()
            .unwrap();
        assert!(!rig.paths().runtime_dir.join(INSTANCE_FILE).exists());
        #[cfg(unix)]
        assert!(!endpoints.control.exists() && !endpoints.signing.exists());
        #[cfg(windows)]
        assert!(
            heimdall_ipc::windows::connect(&endpoints.control)
                .await
                .is_err(),
            "the pipe is gone"
        );
        let again = rig.service().await;
        assert_eq!(again.environment(), &env_id());
        assert_eq!(rig.ledger_entries(), 1);
    }

    /// Shutdown is never accepted from a limited consumer (on any session,
    /// attended or not), is idempotent for the owner (a repeat answers `OK` with
    /// `already_stopping: true`), and starts the drain only from the reply hook,
    /// after the answer was written.
    #[tokio::test]
    async fn shutdown_refused_for_a_limited_consumer_and_idempotent_for_the_owner() {
        use heimdall_app::Attendance;
        use heimdall_ipc::session::Dispatcher as _;
        use heimdall_runtime::dispatch::{EventRelay, OperationsDispatcher};

        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let svc = rig.service().await;
        let relay_stop = CancellationToken::new();
        let relay = EventRelay::spawn(svc.operations(), relay_stop.clone());
        let stop = CancellationToken::new();
        let d = OperationsDispatcher::new(svc.operations().clone(), relay, rig.clock.clone())
            .with_service_control(stop.clone());
        let session = SessionInfo {
            principal: PrincipalInfo::OsUserUnix { uid: 501 },
            interaction: InteractionMode::Interactive,
            attended: true,
        };
        for attendance in [Attendance::Unattended, Attendance::Attended { since: t0() }] {
            let limited = Caller {
                context: CallerContext {
                    principal: PrincipalRef::UnixUser { uid: 501 },
                    role: ClientRole::LimitedConsumer,
                },
                attendance,
                interaction: InteractionMode::Interactive,
            };
            let env = d.handle_as(&limited, shutdown_request()).await;
            assert_no_canary(&serde_json::to_string(&env).unwrap());
            assert_eq!(env.code, Code::CapabilityUnavailable, "{env:?}");
            d.replied(&session, "shutdown", &env.code);
            assert!(
                !stop.is_cancelled(),
                "a limited consumer never stops the service"
            );
        }
        // Owner, unattended: OK; nothing stops until the reply hook runs.
        let first = d
            .handle(
                &SessionInfo {
                    attended: false,
                    ..session.clone()
                },
                shutdown_request(),
            )
            .await;
        assert_eq!(first.code, Code::Ok);
        assert_eq!(first.data["already_stopping"], false);
        assert!(
            !stop.is_cancelled(),
            "the drain waits for the reply to be written"
        );
        d.replied(&session, "shutdown", &first.code);
        assert!(stop.is_cancelled());
        // Repeated (same or another session): idempotent.
        for _ in 0..2 {
            let again = d.handle(&session, shutdown_request()).await;
            assert_eq!(again.code, Code::Ok);
            assert_eq!(again.data["stopping"], true);
            assert_eq!(again.data["already_stopping"], true);
            d.replied(&session, "shutdown", &again.code);
        }
        // A dispatcher without service control does not support the request.
        let plain = OperationsDispatcher::new(
            svc.operations().clone(),
            EventRelay::spawn(svc.operations(), relay_stop.clone()),
            rig.clock.clone(),
        );
        assert_eq!(
            plain.handle(&session, shutdown_request()).await.code,
            Code::UsageError
        );
        relay_stop.cancel();
    }

    /// A slow adapter (`prepare` takes 800 ms) in front of the fake.
    struct SlowAdapter {
        inner: Arc<CountingAdapter>,
        entered: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CredentialAdapter for SlowAdapter {
        fn descriptor(&self) -> &AdapterDescriptor {
            self.inner.descriptor()
        }
        // ADR-0007 §12.26 item 2: no default bodies; this test adapter reads no
        // source and its bounded call is its own `prepare`.
        fn read_sources(
            &self,
            _pairs: &[heimdall_app::ports::PreparePair],
        ) -> heimdall_app::ports::IntegrationSnapshot {
            heimdall_app::ports::IntegrationSnapshot::default()
        }
        fn prepare_from<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            req: heimdall_app::ports::PrepareRequest<'life1>,
            _sources: &'life2 heimdall_app::ports::IntegrationSnapshot,
        ) -> AdapterFut<'async_trait, PrepareOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            self.prepare(req)
        }
        fn prepare<'life0, 'life1, 'async_trait>(
            &'life0 self,
            req: heimdall_app::ports::PrepareRequest<'life1>,
        ) -> AdapterFut<'async_trait, PrepareOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.entered.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(800)).await;
                self.inner.prepare(req).await
            })
        }
        fn renew<'life0, 'life1, 'async_trait>(
            &'life0 self,
            req: heimdall_app::ports::PrepareRequest<'life1>,
        ) -> AdapterFut<'async_trait, PrepareOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.renew(req)
        }
        fn reconcile<'life0, 'life1, 'life2, 'async_trait>(
            &'life0 self,
            grant: &'life1 heimdall_contract::ids::GrantId,
            effect_token: &'life2 str,
        ) -> AdapterFut<'async_trait, heimdall_app::ports::ReconcileOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            'life2: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.reconcile(grant, effect_token)
        }
        fn revoke<'life0, 'life1, 'async_trait>(
            &'life0 self,
            grant: &'life1 heimdall_contract::ids::GrantId,
            now: Timestamp,
        ) -> AdapterFut<'async_trait, heimdall_app::ports::RevokeOutcome>
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            self.inner.revoke(grant, now)
        }
    }

    /// Graceful drain: an operation in flight when the owner's `Shutdown` arrives
    /// (its `prepare` is still running) completes its durable steps before the
    /// service exits: once `run` has returned, the store records it `succeeded`
    /// with its `Confirmed` receipt and exactly one effect, and a same-key retry
    /// against the next instance replays it without a second effect.
    #[tokio::test]
    async fn shutdown_lets_an_in_flight_durable_step_complete_before_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let rig = Rig::new(&tmp);
        let counting = Arc::new(CountingAdapter {
            inner: rig.fake(vec![FakeStep::Prepare(outcome())]),
            prepares: std::sync::atomic::AtomicUsize::new(0),
        });
        let entered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut options = test_options(rig.clock.clone(), rig.sync.clone());
        options.adapters = vec![Arc::new(SlowAdapter {
            inner: counting.clone(),
            entered: entered.clone(),
        }) as Arc<dyn CredentialAdapter>];
        let svc = Service::start_with(
            rig.paths(),
            Config::default(),
            options,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let control = svc.endpoints().control.clone();
        let store = svc.store().clone();
        let running = tokio::spawn(svc.run());

        let mut c = control_client(&control, InteractionMode::NonInteractive).await;
        let mut req = ensure_req("req-fl", "work-fl", Some("1h"));
        req.wait = WaitMode::Async;
        let accepted = c
            .request(heimdall_contract::request::Request::Ensure(req))
            .await
            .unwrap();
        assert_eq!(accepted.code, Code::Accepted, "{accepted:?}");
        let op = accepted.operation_id.clone().unwrap();
        // The prepare is in flight.
        let start = std::time::Instant::now();
        while entered.load(Ordering::SeqCst) == 0 {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "prepare never started"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(rig.ledger_entries(), 0, "the effect is not applied yet");
        let env = c.request(shutdown_request()).await.unwrap();
        assert_eq!(env.code, Code::Ok);
        expect_goodbye(&mut c).await;
        tokio::time::timeout(Duration::from_secs(30), running)
            .await
            .expect("run returns")
            .unwrap()
            .unwrap();

        // After exit: the in-flight operation reached its durable end.
        let (state, receipts) = store
            .transaction(|tx| {
                let state = tx.operation(&op)?.map(|o| o.state);
                Ok((state, tx.stage_receipts(&op)?))
            })
            .unwrap();
        assert_eq!(state, Some(OperationState::Succeeded));
        assert!(
            receipts
                .iter()
                .any(|r| matches!(r.effect, EffectReceipt::Confirmed { .. })),
            "the effect's receipt was persisted before exit"
        );
        assert_eq!(rig.ledger_entries(), 1);
        assert!(!rig.paths().runtime_dir.join(INSTANCE_FILE).exists());
        drop(store);

        // The next instance replays it for the same caller (the principal the
        // endpoint authenticates; idempotency keys are per principal): same
        // operation, no second effect.
        let fake = rig.fake(vec![FakeStep::Prepare(outcome())]);
        let token = CancellationToken::new();
        let next = Service::start_with(
            rig.paths(),
            Config::default(),
            rig.options(&fake),
            token.clone(),
        )
        .await
        .unwrap();
        let control = next.endpoints().control.clone();
        let running = tokio::spawn(next.run());
        let mut c = control_client(&control, InteractionMode::NonInteractive).await;
        let replay = c
            .request(heimdall_contract::request::Request::Ensure(ensure_req(
                "req-fl",
                "work-fl",
                Some("1h"),
            )))
            .await
            .unwrap();
        assert_no_canary(&serde_json::to_string(&replay).unwrap());
        assert_eq!(replay.code, Code::AccessReady, "{replay:?}");
        assert_eq!(replay.operation_id.as_ref(), Some(&op));
        assert_eq!(rig.ledger_entries(), 1);
        assert_eq!(counting.prepares.load(Ordering::SeqCst), 1);
        drop(c);
        token.cancel();
        running.await.unwrap().unwrap();
    }
}

// ===========================================================================
// ADR-0006 §13.6 item 4: the jittered retry delay is bounded (property)
// ===========================================================================

mod jitter_props {
    use std::time::Duration;

    use heimdall_app::reconcile::Backoff;
    use heimdall_runtime::supervisor::{FixedJitter, Jitter, RandomJitter, retry_delay};
    use proptest::prelude::*;
    use proptest::test_runner::{FileFailurePersistence, RngSeed};

    /// 256 cases, fixed seed unless `PROPTEST_RNG_SEED` is set (reproduces).
    fn config() -> ProptestConfig {
        let mut c = ProptestConfig {
            cases: 256,
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            ..ProptestConfig::default()
        };
        if matches!(c.rng_seed, RngSeed::Random) {
            c.rng_seed = RngSeed::Fixed(0x4a49_5454_4552_3133);
        }
        c
    }

    proptest! {
        #![proptest_config(config())]

        /// Every jittered delay lies in `[delay/2, delay]` and never exceeds the
        /// cap; a whole retry schedule is at most the unjittered one and at least
        /// half of it, so jitter never lengthens recovery past the bound.
        #[test]
        fn jittered_retry_delays_stay_within_the_bounded_backoff(
            base_ms in 1u64..5_000,
            cap_s in 1u64..600,
            max_attempts in 1u32..16,
            units in proptest::collection::vec(0.0f64..=1.0, 1..40),
        ) {
            let backoff = Backoff {
                base: Duration::from_millis(base_ms),
                max: Duration::from_secs(cap_s),
                max_attempts,
            };
            let mut total = Duration::ZERO;
            let mut plain_total = Duration::ZERO;
            for (i, u) in units.iter().enumerate() {
                let attempt = u32::try_from(i).unwrap() + 1;
                let plain = backoff.delay(attempt);
                let d = retry_delay(&backoff, attempt, &FixedJitter(*u));
                prop_assert!(d <= plain, "{d:?} > {plain:?}");
                prop_assert!(d <= backoff.max);
                // Equal jitter: at least half (allowing float rounding of 1 ns).
                prop_assert!(d + Duration::from_nanos(1) >= plain / 2, "{d:?} < {plain:?}/2");
                total += d;
                plain_total += plain;
            }
            prop_assert!(total <= plain_total);
        }
    }

    /// `FixedJitter(1.0)` reproduces the unjittered default schedule exactly (what a
    /// test that pins the plain backoff offsets injects).
    #[test]
    fn fixed_unit_one_is_the_unjittered_schedule() {
        let backoff = Backoff::default();
        for n in 1..=backoff.max_attempts {
            assert_eq!(
                retry_delay(&backoff, n, &FixedJitter(1.0)),
                backoff.delay(n)
            );
        }
    }

    /// The production source yields units in `[0, 1]` and is not constant.
    #[test]
    fn random_jitter_is_in_range_and_varies() {
        let draws: Vec<f64> = (0..64).map(|_| RandomJitter.unit()).collect();
        assert!(draws.iter().all(|u| (0.0..=1.0).contains(u)));
        assert!(draws.windows(2).any(|w| w[0] != w[1]), "not constant");
    }
}

// ===========================================================================
// ADR-0006 §13.8 item 7: the detached child gets only null standard descriptors
// ===========================================================================

#[cfg(unix)]
mod fd_hygiene {
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use heimdall_runtime::launcher::spawn_detached;

    /// Turns [`detached_spawn_probe`] into the probing process; the value is the
    /// report file the detached probe writes.
    const PROBE_ENV: &str = "HEIMDALL_FD_PROBE_REPORT";
    const PROBE_TEST: &str = "fd_hygiene::detached_spawn_probe";

    /// Reports, from inside the detached child, whether descriptors 0-2 are
    /// `/dev/null` and whether descriptor 9 is open. `(true >&9)` runs in a
    /// subshell so a failed redirection never ends the reporting shell.
    const PROBE_SCRIPT: &str = r#"r=""
for n in 0 1 2; do
  if [ /dev/fd/$n -ef /dev/null ]; then r="$r $n=null"; else r="$r $n=other"; fi
done
if (true >&9) 2>/dev/null; then r="$r 9=open"; else r="$r 9=closed"; fi
echo "$r" > "$1.tmp" && mv "$1.tmp" "$1""#;

    fn wait_for(path: &Path, limit: Duration) -> Option<String> {
        let start = Instant::now();
        while start.elapsed() < limit {
            if let Ok(text) = std::fs::read_to_string(path) {
                return Some(text);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// Child-process entry, not a test of its own: re-executed by
    /// `detached_child_receives_only_null_standard_descriptors` with fd 9 open
    /// and not close-on-exec, it starts the probe through the production
    /// `launcher::spawn_detached` and waits for its report.
    #[test]
    #[ignore = "child-process entry for the descriptor test; runs only when re-executed by it"]
    fn detached_spawn_probe() {
        let Some(report) = std::env::var_os(PROBE_ENV) else {
            return;
        };
        let report = PathBuf::from(report);
        let args = [
            OsStr::new("-c"),
            OsStr::new(PROBE_SCRIPT),
            OsStr::new("sh"),
            report.as_os_str(),
        ];
        let mut child = spawn_detached(Path::new("/bin/sh"), &args).unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "probe shell failed: {status:?}");
    }

    #[test]
    fn detached_child_receives_only_null_standard_descriptors() {
        let tmp = tempfile::tempdir().unwrap();
        let report = tmp.path().join("report");
        let exe = std::env::current_exe().unwrap();
        // fd 9 of the probing process: a descriptor it inherited without
        // close-on-exec (as a client can inherit one from its caller).
        let mut probe = Command::new("/bin/sh")
            .arg("-c")
            .arg(r#"exec "$0" "$@" 9>/dev/null"#)
            .arg(&exe)
            .args([PROBE_TEST, "--exact", "--ignored", "--test-threads=1"])
            .env(PROBE_ENV, &report)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let text = wait_for(&report, Duration::from_secs(60));
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(s) = probe.try_wait().unwrap() {
                break Some(s);
            }
            if Instant::now() >= deadline {
                let _ = probe.kill();
                let _ = probe.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            status.is_some_and(|s| s.success()),
            "probing process failed: {status:?}"
        );
        let text = text.expect("the detached probe wrote its report");
        assert_eq!(
            text.split_whitespace().collect::<Vec<_>>(),
            ["0=null", "1=null", "2=null", "9=closed"],
            "the detached child's descriptors"
        );
    }
}
