//! M03 wave 5 (U12), worker A: `access lock-behavior|connection-policy|ensure --strict|
//! revoke`, `destination prefer`, `connections [close]`, the help and discovery goldens
//! (owner: `.m03-wave5-api.md` R1). `e2e_cli_m03` submodule; it reaches the parent's
//! `bin()`, `run()`, `Out`, `enrollment()`, `ca()` through `super::`.
//!
//! **The runtime** is the real binary's own (`heimdall service run`, started on demand by
//! the CLI's launcher) in a scratch `HEIMDALL_HOME`, under the debug build's test
//! configuration: the fake credential adapter, the fixture profile `dev` and policy `pol`
//! (`testcfg`), and `HEIMDALL_TEST_SESSION_LOCK`, a state file the fake session-lock source
//! reads (so a host's real lock state never matters). Everything is loopback-free and
//! disposable: no owner key, agent, keychain or `~/.ssh`. [`Rt`]'s `Drop` runs
//! `heimdall service stop` for the runtime this test started. The processes the connection
//! tests close are `/bin/sleep` children this test spawned, signalled only by the runtime's
//! own verified close and killed otherwise through their `Child` handles.
//!
//! **Owner prompts** run the binary under `script(1)` (a pseudo-terminal; Unix only), as
//! `e2e_cli_m01` does; the in-process half is `m03_cmd::wave5_tests`.
//!
//! **Managed grants** (ADR-0008 §17.25 item 18): [`ManagedPair`] reaches a managed pair
//! through the real binary (its runtime's production managed wiring and its real issuer
//! child over the testkit scratch store), seeding only the enrollment prerequisites (the
//! CA and a verified enrollment; listed there). The managed halves of
//! `access_ensure_strict_reports_strict_disconnect` and
//! `revoke_output_lists_owned_connections_and_ordinary_note` run for real: the real issuer
//! child signs each managed activation's certificate (A2-Q1, fixed by the integrator in
//! the driver's `validity_start`). The renderings are also unit-tested in `output.rs`
//! against the contract's types.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use super::*;

/// A scratch runtime of the real binary.
struct Rt {
    scratch: tempfile::TempDir,
    home: PathBuf,
    account: PathBuf,
    lock: PathBuf,
    /// `HEIMDALL_TEST_SECRET_STORE=scratch` for the runtime's issuer child ([`Rt::managed`]).
    scratch_store: bool,
}

impl Rt {
    /// A scratch home whose session-lock state file reads `lock`.
    fn new(lock: &str) -> Rt {
        let scratch = tempfile::tempdir().unwrap();
        let account = scratch.path().join("account");
        std::fs::create_dir_all(&account).unwrap();
        let lock_file = scratch.path().join("lock-state");
        std::fs::write(&lock_file, lock).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for d in [scratch.path(), account.as_path()] {
                std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        Rt {
            home: scratch.path().join("home"),
            account,
            lock: lock_file,
            scratch,
            scratch_store: false,
        }
    }

    /// [`Rt::new`] whose runtime's issuer child (`internal issuer`, which inherits the
    /// CLI-started runtime's environment) selects the testkit's scratch store
    /// (`HEIMDALL_TEST_SECRET_STORE=scratch`, under `<state>/scratch-secret-store`).
    #[cfg(unix)]
    fn managed(lock: &str) -> Rt {
        let mut rt = Rt::new(lock);
        rt.scratch_store = true;
        rt
    }

    fn env(&self) -> Vec<(&'static str, String)> {
        let mut env = self.base_env();
        if self.scratch_store {
            env.push(("HEIMDALL_TEST_SECRET_STORE", "scratch".to_owned()));
        }
        env
    }

    fn base_env(&self) -> Vec<(&'static str, String)> {
        vec![
            ("HEIMDALL_TEST_ADAPTER", "prepare".to_owned()),
            ("HEIMDALL_TEST_TIME_SYNC", "synchronized".to_owned()),
            (
                "HEIMDALL_TEST_SESSION_LOCK",
                self.lock.to_string_lossy().into_owned(),
            ),
            (
                "HEIMDALL_TEST_SSH_HOME",
                self.account.to_string_lossy().into_owned(),
            ),
        ]
    }

    fn run(&self, args: &[&str]) -> Out {
        let env = self.env();
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        run(&self.home, &self.account, args, &env)
    }

    /// Set the fake lock source's state and wait until the runtime has read it.
    fn set_lock(&self, state: &str) {
        std::fs::write(&self.lock, state).unwrap();
        std::thread::sleep(Duration::from_millis(600));
    }

    fn db(&self) -> PathBuf {
        self.home.join("state").join("state.db")
    }

    /// `access ensure` of the fixture pair h1, returning the result's `data`.
    fn ensure(&self, tag: &str, extra: &[&str]) -> Out {
        let mut args = vec![
            "--json",
            "access",
            "ensure",
            "--profile",
            "dev",
            "--pair",
            "h1:deploy",
            "--work-id",
            tag,
            "--request-id",
            tag,
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    /// Run a command on a pseudo-terminal, typing `input` once the owner prompt shows.
    #[cfg(unix)]
    fn run_pty(&self, args: &[&str], input: &[u8]) -> Out {
        use std::io::{Read as _, Write as _};
        use std::process::Stdio;
        use std::sync::{Arc, Mutex};
        let mut cmd = if cfg!(target_os = "linux") {
            let quoted: Vec<String> = std::iter::once(bin())
                .chain(args.iter().map(|a| (*a).to_owned()))
                .map(|a| format!("'{}'", a.replace('\'', r"'\''")))
                .collect();
            let mut c = std::process::Command::new("script");
            c.args(["-q", "-e", "-c", &quoted.join(" "), "/dev/null"]);
            c
        } else {
            let mut c = std::process::Command::new("script");
            c.args(["-q", "/dev/null", &bin()]).args(args);
            c
        };
        cmd.env_clear()
            .env("HEIMDALL_HOME", &self.home)
            .env("HOME", &self.account)
            .env("PATH", "/usr/bin:/bin")
            .env("GIT_CONFIG_NOSYSTEM", "1");
        for (k, v) in self.env() {
            cmd.env(k, v);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("blocked: script(1) is needed for the pseudo-terminal cases");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut stdout = child.stdout.take().unwrap();
        let sink = seen.clone();
        let reader = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        let start = Instant::now();
        loop {
            let text = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
            if text.contains("[y/N]: ") {
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "exited before the prompt: {text}"
            );
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "no prompt: {text}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input).unwrap();
        stdin.flush().unwrap();
        let code = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s.code().unwrap_or(-1);
            }
            assert!(
                start.elapsed() < Duration::from_secs(120),
                "the pty child did not exit"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(stdin);
        reader.join().unwrap();
        let mut err = String::new();
        if let Some(mut e) = child.stderr.take() {
            let _ = e.read_to_string(&mut err);
        }
        let stdout = String::from_utf8_lossy(&seen.lock().unwrap()).into_owned();
        assert_no_canary(&stdout);
        assert_no_canary(&err);
        Out {
            code,
            stdout,
            stderr: err,
        }
    }
}

impl Drop for Rt {
    fn drop(&mut self) {
        // The runtime this test started, in this test's own home (a no-op when none ran).
        let env = self.env();
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let _ = std::process::Command::new(bin())
            .args(["--json", "service", "stop"])
            .env_clear()
            .env("HEIMDALL_HOME", &self.home)
            .env("HOME", &self.account)
            .env("PATH", "/usr/bin:/bin")
            .envs(env)
            .stdin(std::process::Stdio::null())
            .output();
        let _ = &self.scratch;
    }
}

// ---- the managed pair (ADR-0008 §17.25 item 18) --------------------------------------------

/// The managed pair of [`ManagedPair::set_up`]: destination `h2` (in the fixture profile
/// `dev` and its policy `pol`), account `deploy`, alias `lab2`.
#[cfg(unix)]
const MANAGED_ALIAS: &str = "lab2";

/// The version line of the `ssh` the CLI-started runtime resolves (`PATH=/usr/bin:/bin`),
/// or empty when there is none.
#[cfg(unix)]
fn local_client_version() -> String {
    ["/usr/bin/ssh", "/bin/ssh"]
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .and_then(|p| std::process::Command::new(p).arg("-V").output().ok())
        .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_owned())
        .unwrap_or_default()
}

/// A managed-certificate pair reached through the real binary: what runs for real and
/// what is seeded.
///
/// * **Real:** the CLI-started runtime (`heimdall service run`: the production managed
///   wiring, `ManagedCertificateAdapter`, signer table, binding endpoints), its issuer
///   child (the real binary's `internal issuer` over the testkit scratch store,
///   `HEIMDALL_TEST_SECRET_STORE=scratch`), the catalog (`identity adopt`, `destination
///   add`), `destination prefer … managed`, `setup apply` and `time confirm` (each with
///   its typed `yes` on a pseudo-terminal), and every `access` command after.
/// * **Seeded** in the store (the enrollment prerequisites; the issuer ceremony and the
///   enrollment loop have their own suites): a fresh K_ca put in the scratch store, its
///   `active` CA record and store locator; a `verified` account-form enrollment of
///   `h2/deploy` under that CA, with evidence naming the local client (so the runtime's
///   re-verification pass leaves it `verified`); the CA as the pair's issuing CA. The
///   runtime is restarted after the CA is seeded (`service stop`; the next command starts
///   it) so the issuer child loads it.
///
/// Unix only: the typed confirmations run under `script(1)`.
#[cfg(unix)]
struct ManagedPair;

#[cfg(unix)]
impl ManagedPair {
    fn set_up(rt: &Rt) -> ManagedPair {
        use heimdall_issuer::store::SecretStore as _;
        let key = scratch_key(rt);
        let adopted = rt.run(&[
            "--json",
            "identity",
            "adopt",
            "--pub",
            &key.to_string_lossy(),
        ]);
        assert_eq!(adopted.code, 0, "{adopted:?}");
        let identity = adopted.json()["data"]["identity_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let add = rt.run(&[
            "--json",
            "destination",
            "add",
            MANAGED_ALIAS,
            "--hostname",
            "127.0.0.1",
            "--account",
            "deploy",
            "--identity",
            &identity,
            "--id",
            "h2",
        ]);
        assert_eq!(add.code, 0, "{add:?}");

        // K_ca in the scratch store the issuer child selects (owner-only), then its record.
        let store_dir = rt.home.join("state").join("scratch-secret-store");
        std::fs::create_dir_all(&store_dir).unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&store_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let ca_key = heimdall_credential::cert::SecretCaKey::generate().unwrap();
        let fp = ca_key.fingerprint().unwrap();
        let public = ca_key.public_openssh().unwrap();
        let item = heimdall_testkit::scratch_store::ScratchSecretStore::new(store_dir)
            .put(&fp, &ca_key)
            .unwrap();
        drop(ca_key);
        let now = Timestamp::now();
        let mut record = enrollment(2, EnrollmentState::Verified);
        record.destination = DestinationId::parse("h2").unwrap();
        record.ca_fingerprint = fp.clone();
        record.target.hostname = "127.0.0.1".into();
        record.verified_at = Some(now);
        record.evidence = Some(heimdall_domain::enrollment::EnrollmentEvidence {
            client: local_client_version(),
            server: "SSH-2.0-OpenSSH_fixture".into(),
            operation: heimdall_contract::ids::OperationId::from_random_bytes([2; 16]),
            verified_at: now,
            fresh_until: now.checked_add(Duration::from_secs(30 * 86_400)).unwrap(),
            clock: None,
        });
        let pair = heimdall_domain::scope::AccessPair {
            destination: record.destination.clone(),
            account: record.account.clone(),
        };
        Store::open(&rt.db(), Arc::new(NoFaults))
            .unwrap()
            .transaction(|tx| {
                tx.insert_issuer(&IssuerRecord {
                    ca_fingerprint: fp.clone(),
                    public_key: public.clone(),
                    state: CaState::Active,
                    store_kind: StoreKind::LinuxSecretService,
                    backup_sha256: "ab".repeat(32),
                    backup_created_at: now,
                    restored_without_log: false,
                    created_at: now,
                    retired_at: None,
                })?;
                tx.set_issuer_store_locator(&fp, &item.locator)?;
                tx.seed_enrollment(&record)
            })
            .unwrap();
        let stopped = rt.run(&["--json", "service", "stop"]);
        assert_eq!(stopped.code, 0, "{stopped:?}");
        let prefer = rt.run(&["--json", "destination", "prefer", MANAGED_ALIAS, "managed"]);
        assert_eq!(prefer.code, 0, "{prefer:?}");
        let status = rt.run(&["--json", "issuer", "status"]);
        assert_eq!(status.json()["data"]["state"], "ready", "{status:?}");
        // The pair's issuing CA (E5 records it with the enrollment, after the preference).
        Store::open(&rt.db(), Arc::new(NoFaults))
            .unwrap()
            .transaction(|tx| tx.add_issuing_ca(&pair, &fp, now))
            .unwrap();
        // P names the alias (the preference is pending until applied), and this boot's
        // time is confirmed (the issuer child's read-only gate needs a same-boot reference).
        let applied = rt.run_pty(&["setup", "apply"], b"yes\n");
        assert_eq!(applied.code, 0, "{applied:?}");
        let confirmed = rt.run_pty(&["time", "confirm"], b"yes\n");
        assert_eq!(confirmed.code, 0, "{confirmed:?}");
        ManagedPair
    }

    /// `heimdall --json access ensure` of the managed pair (exit 0 asserted): the real
    /// issuer child signs the activation's certificate.
    fn ensure(rt: &Rt, tag: &str, extra: &[&str]) -> Out {
        let mut args = vec![
            "--json",
            "access",
            "ensure",
            "--profile",
            "dev",
            "--pair",
            "h2:deploy",
            "--work-id",
            tag,
            "--request-id",
            tag,
        ];
        args.extend_from_slice(extra);
        let out = rt.run(&args);
        assert_eq!(out.code, 0, "{out:?}");
        out
    }
}

/// An envelope of the public shape: the six fields, `state` and `code` strings,
/// `warnings` an array, and `data` present.
fn assert_envelope_shape(env: &Value) {
    let o = env
        .as_object()
        .unwrap_or_else(|| panic!("not an object: {env}"));
    for key in [
        "schema_version",
        "state",
        "code",
        "data",
        "warnings",
        "next",
    ] {
        assert!(o.contains_key(key), "{key} missing from {env}");
    }
    assert_eq!(env["schema_version"], "1", "{env}");
    assert!(env["state"].is_string() && env["code"].is_string(), "{env}");
    assert!(env["warnings"].is_array(), "{env}");
    let code = env["code"].as_str().unwrap();
    assert!(
        code.chars().all(|c| c.is_ascii_uppercase() || c == '_'),
        "{code}"
    );
    if env["state"] == "failed" || env["data"].get("error").is_some() {
        let e = &env["data"]["error"];
        assert_eq!(e["code"], env["code"], "{env}");
        assert!(e["message"].is_string(), "{env}");
        assert!(e["effect_status"].is_string(), "{env}");
    }
}

/// `access lock-behavior` and `connection-policy` through the real runtime:
/// * `revoke-on-lock` where the lock signal is `unavailable` is refused
///   (`CAPABILITY_UNAVAILABLE`, `lock_signal_unavailable`, exit 4) before anything is
///   written, in `--json` and in human mode (the reason is printed);
/// * with a usable signal it is narrowing and applies at once, without a decision;
/// * `continue` (widening) without a terminal or with `--non-interactive` exits 3 with
///   `next.decision_ref` and changes nothing; on a terminal, `no`, and end of input
///   change nothing (exit 3) and a typed `yes` applies it;
/// * `connection-policy`: `--existing strict` narrows at once, `--existing graceful` and
///   `--multiplexing owned` widen (exit 3 unattended); neither flag is a usage error.
#[test]
fn access_lock_behavior_refused_where_unavailable() {
    let rt = Rt::new("unavailable");
    let refused = rt.run(&[
        "--json",
        "access",
        "lock-behavior",
        "--policy",
        "pol",
        "revoke-on-lock",
    ]);
    assert_eq!(refused.code, 4, "{refused:?}");
    let env = refused.json();
    assert_envelope_shape(&env);
    assert_eq!(env["code"], "CAPABILITY_UNAVAILABLE", "{refused:?}");
    assert_eq!(env["data"]["error"]["reason"], "lock_signal_unavailable");
    assert_eq!(env["data"]["error"]["effect_status"], "none");
    assert_eq!(env["next"]["action"], "narrow_request");
    let human = rt.run(&[
        "access",
        "lock-behavior",
        "--policy",
        "pol",
        "revoke-on-lock",
    ]);
    assert_eq!(human.code, 4, "{human:?}");
    assert!(
        human.stderr.contains("reason: lock_signal_unavailable"),
        "{human:?}"
    );
    assert!(human.stderr.contains("session-lock signal"), "{human:?}");

    // A usable signal: narrowing, immediate, no decision. The refusals above wrote
    // nothing: this is the policy's first revision change (1 -> 2).
    rt.set_lock("unlocked");
    let set = rt.run(&[
        "--json",
        "access",
        "lock-behavior",
        "--policy",
        "pol",
        "revoke-on-lock",
    ]);
    assert_eq!(set.code, 0, "{set:?}");
    assert_envelope_shape(&set.json());
    assert_eq!(set.json()["data"]["changed"], true, "{set:?}");
    assert_eq!(set.json()["data"]["revision"], 2, "{set:?}");
    let again = rt.run(&[
        "--json",
        "access",
        "lock-behavior",
        "--policy",
        "pol",
        "revoke-on-lock",
    ]);
    assert_eq!(again.json()["data"]["changed"], false, "{again:?}");
    assert_eq!(again.json()["data"]["revision"], 2);

    // `continue` widens: nothing is sent without the owner (exit 3, a decision to
    // refer to), whether or not a terminal is asked for.
    for extra in [&["--non-interactive"][..], &[][..]] {
        let mut args = vec!["--json"];
        args.extend_from_slice(extra);
        args.extend(["access", "lock-behavior", "--policy", "pol", "continue"]);
        let out = rt.run(&args);
        assert_eq!(out.code, 3, "{args:?}: {out:?}");
        let env = out.json();
        assert_envelope_shape(&env);
        assert_eq!(env["code"], "INTERACTION_REQUIRED");
        assert!(env["next"]["decision_ref"].is_string(), "{out:?}");
        assert_eq!(env["data"]["error"]["effect_status"], "none");
    }
    let unchanged = rt.run(&[
        "--json",
        "access",
        "lock-behavior",
        "--policy",
        "pol",
        "revoke-on-lock",
    ]);
    assert_eq!(unchanged.json()["data"]["changed"], false, "{unchanged:?}");
    assert_eq!(unchanged.json()["data"]["revision"], 2, "still revision 2");

    // `connection-policy`.
    let neither = rt.run(&["--json", "access", "connection-policy", "--policy", "pol"]);
    assert_eq!(neither.code, 2, "{neither:?}");
    assert!(neither.message().contains("--existing or --multiplexing"));
    let strict = rt.run(&[
        "--json",
        "access",
        "connection-policy",
        "--policy",
        "pol",
        "--existing",
        "strict",
    ]);
    assert_eq!(strict.code, 0, "{strict:?}");
    assert_eq!(strict.json()["data"]["changed"], true);
    assert_eq!(strict.json()["data"]["revision"], 3);
    for flags in [["--existing", "graceful"], ["--multiplexing", "owned"]] {
        let mut args = vec!["--json", "access", "connection-policy", "--policy", "pol"];
        args.extend(flags);
        let out = rt.run(&args);
        assert_eq!(out.code, 3, "{flags:?}: {out:?}");
        assert!(out.json()["next"]["decision_ref"].is_string(), "{out:?}");
    }
    let narrowing = rt.run(&[
        "--json",
        "access",
        "connection-policy",
        "--policy",
        "pol",
        "--multiplexing",
        "disabled",
    ]);
    assert_eq!(narrowing.code, 0, "{narrowing:?}");

    // On a terminal: no, and end of input, send nothing; a typed yes applies.
    #[cfg(unix)]
    {
        let args = [
            "--json",
            "access",
            "lock-behavior",
            "--policy",
            "pol",
            "continue",
        ];
        for (input, why) in [
            (&b"no\n"[..], "answered no"),
            (&b"\x04"[..], "end of input"),
        ] {
            let out = rt.run_pty(&args, input);
            assert_eq!(out.code, 3, "{why}: {out:?}");
            assert!(out.stdout.contains("not confirmed"), "{why}: {out:?}");
            assert!(out.stdout.contains(why), "{why}: {out:?}");
        }
        let still = rt.run(&[
            "--json",
            "access",
            "lock-behavior",
            "--policy",
            "pol",
            "revoke-on-lock",
        ]);
        assert_eq!(
            still.json()["data"]["changed"],
            false,
            "nothing was sent: {still:?}"
        );
        let yes = rt.run_pty(&args, b"yes\n");
        assert_eq!(yes.code, 0, "{yes:?}");
        let revoke_again = rt.run(&[
            "--json",
            "access",
            "lock-behavior",
            "--policy",
            "pol",
            "revoke-on-lock",
        ]);
        assert_eq!(
            revoke_again.json()["data"]["changed"],
            true,
            "the typed yes applied `continue`: {revoke_again:?}"
        );
    }
}

/// `access ensure --strict` through the real runtime.
/// * **Existing access** (the fixture adapter): the request is accepted and the strict
///   choice reaches the grant's origin (the strictest-wins record the connection
///   supervisor reads); a plain `ensure` records none. The result carries no
///   `connection_policy`, and the CLI prints no connection claim for it.
/// * **Managed** (ADR-0008 §17.25 item 18; [`ManagedPair`], Unix): the result's
///   `data.connection_policy` is `strict` with exactly the D8 strict wording for the
///   pair's selection (`DEADLINE_STRICT_EXCLUSIVE`, else `DEADLINE_STRICT_NOT_EXCLUSIVE`,
///   plus the owned-masters sentence when owned masters apply), and the human output
///   prints the policy and that wording verbatim, all through the real binary and its
///   real issuer child. The rendering is also `output::tests::
///   access_ensure_strict_reports_strict_disconnect` (unit level, the contract's types).
#[test]
fn access_ensure_strict_reports_strict_disconnect() {
    #[cfg(unix)]
    managed_strict_half();
    let rt = Rt::new("unlocked");
    let plain = rt.ensure("plain", &[]);
    assert_eq!(plain.code, 0, "{plain:?}");
    assert_envelope_shape(&plain.json());
    let strict = rt.ensure("strict", &["--strict"]);
    assert_eq!(strict.code, 0, "{strict:?}");
    assert_envelope_shape(&strict.json());
    assert_eq!(strict.json()["code"], "ACCESS_READY");
    assert!(strict.json()["data"].get("connection_policy").is_none());
    let human = rt.run(&[
        "access",
        "ensure",
        "--profile",
        "dev",
        "--pair",
        "h1:deploy",
        "--work-id",
        "strict",
        "--request-id",
        "strict2",
        "--strict",
    ]);
    assert_eq!(human.code, 0, "{human:?}");
    assert!(!human.stdout.contains("Connection policy"), "{human:?}");

    let origin = |grant: &str| {
        let store = heimdall_store::Store::open_read_only(&rt.db(), Arc::new(NoFaults)).unwrap();
        let grant = heimdall_contract::ids::GrantId::parse(grant).unwrap();
        store
            .transaction(|tx| tx.grant_origin(&grant))
            .unwrap()
            .expect("the grant has an origin")
    };
    let existing = |o: &heimdall_domain::grant::GrantOrigin| o.connection.map(|c| c.existing);
    let strict_grant = strict.json()["data"]["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        existing(&origin(&strict_grant)),
        Some(heimdall_contract::managed::ExistingConnectionsMode::Strict),
        "`--strict` reached the grant's origin"
    );
    let plain_grant = plain.json()["data"]["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // The two requests share the policy-resolved authority, hence maybe one grant; a
    // plain `ensure` made first records no connection choice of its own.
    if plain_grant != strict_grant {
        assert_eq!(existing(&origin(&plain_grant)), None);
    }
}

/// `access revoke` through the real runtime.
/// * **Managed** ([`ManagedPair`], Unix): a revoke lists the grant's owned connections in
///   `data.owned_connections[]` (one `/bin/sleep` row of this test, seeded with its
///   verified identity, is `closed` and its process ends) and carries the note
///   `ordinary_connections_not_closed`; the human output shows the count and the
///   ordinary-`ssh` sentence (`output::ORDINARY_CONNECTIONS_NOTE`), on managed grants
///   the real issuer child signed; the rendering is also `output::tests::
///   revoke_output_lists_owned_connections_and_ordinary_note` (unit level).
/// * **Existing access:** M02's result and no managed claim: no owned-connection list and
///   no ordinary-`ssh` note.
#[test]
fn revoke_output_lists_owned_connections_and_ordinary_note() {
    #[cfg(unix)]
    managed_revoke_half();
    let rt = Rt::new("unlocked");
    let ensured = rt.ensure("rv", &[]);
    assert_eq!(ensured.code, 0, "{ensured:?}");
    let grant = ensured.json()["data"]["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let revoked = rt.run(&["--json", "access", "revoke", &grant, "--request-id", "rv-1"]);
    assert_eq!(revoked.code, 0, "{revoked:?}");
    let env = revoked.json();
    assert_envelope_shape(&env);
    assert_eq!(env["data"]["local_applied"], true, "{revoked:?}");
    for managed_only in ["owned_connections", "notes", "remote_effects"] {
        assert!(
            env["data"].get(managed_only).is_none(),
            "{managed_only}: {revoked:?}"
        );
    }
    let again = rt.run(&["access", "revoke", &grant, "--request-id", "rv-2"]);
    assert_eq!(again.code, 0, "{again:?}");
    assert!(!again.stdout.contains("Owned connections"), "{again:?}");
    assert!(!again.stdout.contains("Note:"), "{again:?}");
}

/// The strict wording the runtime's D8 rule gives a managed result's `data`: by the
/// pair's identity selection, with the owned-masters sentence when owned masters apply
/// (the `localenv` and `adapters` constants, never retyped).
#[cfg(unix)]
fn strict_wording_of(data: &Value) -> String {
    use heimdall_localenv::projection::plan::{
        DEADLINE_STRICT_EXCLUSIVE, DEADLINE_STRICT_NOT_EXCLUSIVE,
    };
    let selection = data["consumer"]["pairs"][0]["identity_selection"].as_str();
    let base = if selection == Some("exclusive") {
        DEADLINE_STRICT_EXCLUSIVE
    } else {
        DEADLINE_STRICT_NOT_EXCLUSIVE
    };
    if data["connection_policy"]["multiplexing"] == "owned_masters" {
        format!(
            "{base} {}",
            heimdall_adapters::managed::report::OWNED_MASTERS_DISCLOSURE
        )
    } else {
        base.to_owned()
    }
}

/// The managed half of `access_ensure_strict_reports_strict_disconnect`.
#[cfg(unix)]
fn managed_strict_half() {
    let rt = Rt::managed("unlocked");
    let _pair = ManagedPair::set_up(&rt);
    let strict = ManagedPair::ensure(&rt, "m-strict", &["--strict"]);
    let env = strict.json();
    assert_envelope_shape(&env);
    assert_eq!(env["code"], "ACCESS_READY", "{strict:?}");
    let data = &env["data"];
    assert_eq!(
        data["credential_mechanism"], "managed_certificate",
        "{data}"
    );
    assert_eq!(data["connection_policy"]["existing"], "strict", "{data}");
    let wording = strict_wording_of(data);
    assert_eq!(
        data["connection_policy"]["wording"],
        wording.as_str(),
        "{data}"
    );
    let human = rt.run(&[
        "access",
        "ensure",
        "--profile",
        "dev",
        "--pair",
        "h2:deploy",
        "--work-id",
        "m-strict-human",
        "--request-id",
        "m-strict-human",
        "--strict",
    ]);
    assert_eq!(human.code, 0, "{human:?}");
    assert!(
        human
            .stdout
            .contains("Connection policy: existing strict, multiplexing "),
        "{human:?}"
    );
    assert!(
        human.stdout.lines().any(|l| l == wording),
        "the runtime's wording, verbatim: {human:?}"
    );
    // ⟨ADR-0008 §17.27 item 9; W5-R06⟩ `destination list` of the runtime's real `items[]`:
    // the managed pair's computed connection policy and its wording, verbatim.
    let inspected = rt.run(&["--json", "inspect", "destinations"]);
    assert_eq!(inspected.code, 0, "{inspected:?}");
    let lab2 = inspected.json()["data"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("the runtime lists `items`: {inspected:?}"))
        .iter()
        .find(|d| d["alias"] == MANAGED_ALIAS)
        .cloned()
        .unwrap();
    let policy = &lab2["preference"]["connection_policy"];
    let head = format!(
        "{MANAGED_ALIAS}: connection policy: existing {}, multiplexing {}.",
        policy["existing"].as_str().unwrap(),
        policy["multiplexing"].as_str().unwrap()
    );
    let listed = rt.run(&["destination", "list"]);
    assert_eq!(listed.code, 0, "{listed:?}");
    assert!(
        listed.stdout.lines().any(|l| l == head),
        "{head}: {listed:?}"
    );
    assert!(
        listed
            .stdout
            .lines()
            .any(|l| l == policy["wording"].as_str().unwrap()),
        "the runtime's wording, verbatim: {listed:?}"
    );
}

/// The managed half of `revoke_output_lists_owned_connections_and_ordinary_note`.
#[cfg(unix)]
fn managed_revoke_half() {
    use heimdall_contract::ids::{BindingId, ConnectionId, GrantId};
    use heimdall_contract::managed::ConnectionKind;
    use heimdall_contract::request::ProcessHolder;
    use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState};

    let rt = Rt::managed("unlocked");
    let _pair = ManagedPair::set_up(&rt);
    let ensured = ManagedPair::ensure(&rt, "m-rv", &[]);
    let data = ensured.json()["data"].clone();
    let binding = BindingId::parse(data["binding_id"].as_str().unwrap()).unwrap();
    let grant = GrantId::parse(data["grant_id"].as_str().unwrap()).unwrap();
    // One owned connection of the grant: this test's `/bin/sleep`, its identity verified.
    let mut owned = Sleeper::start();
    let id = ConnectionId::from_random_bytes([0x44; 16]);
    Store::open(&rt.db(), Arc::new(NoFaults))
        .unwrap()
        .transaction(|tx| {
            tx.set_binding_holder(
                &binding,
                &ProcessHolder {
                    pid: owned.child.id(),
                    started_at: owned.token.clone(),
                },
            )?;
            tx.insert_owned_connection(&OwnedConnection {
                id: id.clone(),
                kind: ConnectionKind::Dedicated,
                binding: binding.clone(),
                grant: grant.clone(),
                pid: owned.child.id(),
                start_token: owned.token.clone(),
                image: owned.image.clone(),
                control_path: None,
                generation: 0,
                state: OwnedConnectionState::Up,
                started_at: Timestamp::now(),
            })
        })
        .unwrap();
    let revoked = rt.run(&[
        "--json",
        "access",
        "revoke",
        grant.as_str(),
        "--request-id",
        "m-rv-1",
    ]);
    assert_eq!(revoked.code, 0, "{revoked:?}");
    let env = revoked.json();
    assert_envelope_shape(&env);
    assert_eq!(env["data"]["local_applied"], true, "{revoked:?}");
    let rows = env["data"]["owned_connections"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{revoked:?}");
    assert_eq!(rows[0]["id"], id.as_str());
    assert_eq!(rows[0]["kind"], "dedicated");
    assert_eq!(rows[0]["state"], "closed", "{revoked:?}");
    assert_eq!(
        env["data"]["notes"],
        serde_json::json!(["ordinary_connections_not_closed"]),
        "{revoked:?}"
    );
    assert!(
        owned.ended_within(Duration::from_secs(10)),
        "the owned connection's process is still running"
    );
    // Human: another managed grant (its own work), revoked: the count and the note.
    let second = ManagedPair::ensure(&rt, "m-rv-human", &[]).json()["data"]["grant_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let human = rt.run(&["access", "revoke", &second, "--request-id", "m-rv-2"]);
    assert_eq!(human.code, 0, "{human:?}");
    assert!(human.stdout.contains("Owned connections: "), "{human:?}");
    assert!(
        human
            .stdout
            .lines()
            .any(|l| l.starts_with("Note: ") && l.contains("ordinary ssh")),
        "{human:?}"
    );
}

/// A `/bin/sleep` child of this test and the start token the runtime reads for it.
#[cfg(unix)]
struct Sleeper {
    child: std::process::Child,
    token: String,
    image: String,
}

#[cfg(unix)]
impl Sleeper {
    fn start() -> Sleeper {
        let child = std::process::Command::new("/bin/sleep")
            .arg("600")
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let token = heimdall_runtime::platform::process_start_time(child.id())
            .expect("the child has a start token");
        let image = std::fs::canonicalize("/bin/sleep")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        Sleeper {
            child,
            token,
            image,
        }
    }

    /// Wait (bounded) for the process to end; `true` when it did.
    fn ended_within(&mut self, bound: Duration) -> bool {
        let end = Instant::now() + bound;
        while Instant::now() < end {
            if self.child.try_wait().unwrap().is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

#[cfg(unix)]
impl Drop for Sleeper {
    fn drop(&mut self) {
        // Only this test's own child, through its handle.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `connections` lists the owned connections and `connections close <id>` closes one
/// (owner only), through the real runtime with two owned rows seeded for a grant of an
/// `ensure`:
/// * the list (`--json` and human) shows both, with kind, destination, binding, grant and
///   policy; PIDs are never shown;
/// * closing the verified one ends exactly its process (SIGTERM through the runtime's
///   verified close) and exits 0; closing it again answers the same state;
/// * closing the one whose process identity cannot be verified (a wrong start token)
///   does **not** signal it: the runtime answers `OK` with `state: unverified`, so the
///   exit is 0 (ADR-0008 §17.25 item 16: the exit follows the envelope code), the human
///   text says plainly that nothing was closed or signalled, and the process is still
///   running;
/// * an unknown ID is `NOT_FOUND` (2), a malformed one a usage error (2); with no runtime
///   the listing is `SERVICE_UNAVAILABLE` (5) and starts none.
///
/// Unix only: the Windows owned connection is a contained `ssh.exe` registered by the
/// launcher (U7's native tests); a `/bin/sleep` fixture does not exist there.
#[cfg(unix)]
#[test]
fn connections_list_and_owner_close() {
    use heimdall_contract::ids::{BindingId, ConnectionId, GrantId};
    use heimdall_contract::managed::ConnectionKind;
    use heimdall_contract::request::ProcessHolder;
    use heimdall_domain::managed::{OwnedConnection, OwnedConnectionState};

    // No runtime: a read, never starting one.
    let none = Rt::new("unlocked");
    let off = none.run(&["--json", "connections"]);
    assert_eq!(off.code, 5, "{off:?}");
    assert_eq!(off.json()["code"], "SERVICE_UNAVAILABLE");
    assert!(!none.home.join("run").join("instance.json").exists());

    let rt = Rt::new("unlocked");
    let ensured = rt.ensure("conn", &[]);
    assert_eq!(ensured.code, 0, "{ensured:?}");
    let data = ensured.json()["data"].clone();
    let binding = BindingId::parse(data["binding_id"].as_str().unwrap()).unwrap();
    let grant = GrantId::parse(data["grant_id"].as_str().unwrap()).unwrap();
    let empty = rt.run(&["--json", "connections"]);
    assert_eq!(empty.code, 0, "{empty:?}");
    assert_envelope_shape(&empty.json());
    assert_eq!(empty.json()["data"]["connections"], serde_json::json!([]));
    let human = rt.run(&["connections"]);
    assert!(human.stdout.contains("No owned connections."), "{human:?}");

    let (mut verified, mut unverified) = (Sleeper::start(), Sleeper::start());
    let id_ok = ConnectionId::from_random_bytes([0x11; 16]);
    let id_bad = ConnectionId::from_random_bytes([0x22; 16]);
    let row = |id: &ConnectionId, s: &Sleeper, token: &str| OwnedConnection {
        id: id.clone(),
        kind: ConnectionKind::Dedicated,
        binding: binding.clone(),
        grant: grant.clone(),
        pid: s.child.id(),
        start_token: token.to_owned(),
        image: s.image.clone(),
        control_path: None,
        generation: 0,
        state: OwnedConnectionState::Up,
        started_at: Timestamp::now(),
    };
    {
        let store = Store::open(&rt.db(), Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                tx.set_binding_holder(
                    &binding,
                    &ProcessHolder {
                        pid: verified.child.id(),
                        started_at: verified.token.clone(),
                    },
                )?;
                tx.insert_owned_connection(&row(&id_ok, &verified, &verified.token))?;
                tx.insert_owned_connection(&row(&id_bad, &unverified, "not-its-start-token"))
            })
            .unwrap();
    }

    let listed = rt.run(&["--json", "connections"]);
    assert_eq!(listed.code, 0, "{listed:?}");
    let env = listed.json();
    assert_envelope_shape(&env);
    let rows = env["data"]["connections"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{listed:?}");
    for r in rows {
        assert_eq!(r["kind"], "dedicated");
        assert_eq!(r["state"], "up");
        assert_eq!(r["destination_id"], "h1");
        assert_eq!(r["binding_id"], binding.as_str());
        assert_eq!(r["grant_id"], grant.as_str());
        assert!(r["policy"]["existing"].is_string(), "{r}");
        assert!(r.get("pid").is_none(), "a PID is never exposed: {r}");
    }
    let human = rt.run(&["connections"]);
    for id in [&id_ok, &id_bad] {
        assert!(human.stdout.contains(id.as_str()), "{human:?}");
    }
    assert!(human.stdout.contains("destination h1"), "{human:?}");
    assert!(human.stdout.contains("are not listed"), "{human:?}");
    assert!(
        !human.stdout.contains(&verified.child.id().to_string()),
        "no PID"
    );

    // The unverifiable one: reported, never signalled.
    let bad = rt.run(&["--json", "connections", "close", id_bad.as_str()]);
    assert_eq!(bad.code, 0, "the exit follows the envelope code: {bad:?}");
    assert_eq!(
        bad.json()["code"],
        "OK",
        "the runtime's answer is unchanged: {bad:?}"
    );
    assert_eq!(bad.json()["data"]["state"], "unverified", "{bad:?}");
    assert!(
        !unverified.ended_within(Duration::from_millis(500)),
        "it was signalled"
    );
    let human_bad = rt.run(&["connections", "close", id_bad.as_str()]);
    assert!(
        human_bad.stdout.contains("was not closed")
            && human_bad.stdout.contains("nothing was signalled"),
        "{human_bad:?}"
    );
    assert!(!human_bad.stdout.contains("Closed owned"), "{human_bad:?}");
    assert_eq!(human_bad.code, 0, "{human_bad:?}");
    assert!(
        !unverified.ended_within(Duration::from_millis(200)),
        "it was signalled"
    );

    // The verified one: closed, its process ended.
    let ok = rt.run(&["--json", "connections", "close", id_ok.as_str()]);
    assert_eq!(ok.code, 0, "{ok:?}");
    assert_envelope_shape(&ok.json());
    assert_eq!(ok.json()["data"]["state"], "closed", "{ok:?}");
    assert_eq!(ok.json()["data"]["kind"], "dedicated");
    assert!(
        verified.ended_within(Duration::from_secs(10)),
        "the process is still running"
    );
    let twice = rt.run(&["connections", "close", id_ok.as_str()]);
    assert_eq!(twice.code, 0, "{twice:?}");
    assert!(
        twice.stdout.contains("Closed owned connection"),
        "{twice:?}"
    );

    // Neither is listed any more (closed and unverified rows are not live).
    let after = rt.run(&["--json", "connections"]);
    assert_eq!(
        after.json()["data"]["connections"],
        serde_json::json!([]),
        "{after:?}"
    );

    // Unknown and malformed IDs.
    let unknown = ConnectionId::from_random_bytes([0x33; 16]);
    let nf = rt.run(&["--json", "connections", "close", unknown.as_str()]);
    assert_eq!(nf.code, 2, "{nf:?}");
    assert_eq!(nf.json()["code"], "NOT_FOUND");
    let malformed = rt.run(&["--json", "connections", "close", "not-a-connection"]);
    assert_eq!(malformed.code, 2, "{malformed:?}");
    assert_eq!(malformed.json()["code"], "USAGE_ERROR");
}

/// `destination prefer <alias> managed|existing` through the real runtime:
/// * an observed alias and an unknown one are refused (`observed_alias_unmanaged` exit 4;
///   `NOT_FOUND` exit 2) before anything is written;
/// * `managed` for a pair without a verified enrollment is `pair_not_enrolled` (exit 4)
///   and the human text names the `enroll` command;
/// * with a verified enrollment (seeded in the scratch store) `managed` is journaled,
///   `changed`, `projection: pending`, and the text says it reaches `ssh` only through
///   `setup apply`; `inspect destinations` then carries the preference; `existing` flips
///   it back; repeating either is `changed: false`.
#[test]
fn destination_prefer_resolves_alias_and_journals_the_preference() {
    let rt = Rt::new("unlocked");
    let key = scratch_key(&rt);
    let adopted = rt.run(&[
        "--json",
        "identity",
        "adopt",
        "--pub",
        &key.to_string_lossy(),
    ]);
    assert_eq!(adopted.code, 0, "{adopted:?}");
    let identity = adopted.json()["data"]["identity_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let add = rt.run(&[
        "--json",
        "destination",
        "add",
        "lab1",
        "--hostname",
        "lab1.example.invalid",
        "--account",
        "deploy",
        "--identity",
        &identity,
        "--id",
        "dst-lab1",
    ]);
    assert_eq!(add.code, 0, "{add:?}");
    let observed = rt.run(&["--json", "destination", "add", "seen", "--observed"]);
    assert_eq!(observed.code, 0, "{observed:?}");

    let seen = rt.run(&["--json", "destination", "prefer", "seen", "managed"]);
    assert_eq!(seen.code, 4, "{seen:?}");
    assert_envelope_shape(&seen.json());
    assert_eq!(
        seen.json()["data"]["error"]["reason"],
        "observed_alias_unmanaged"
    );
    let missing = rt.run(&["--json", "destination", "prefer", "nope", "managed"]);
    assert_eq!(missing.code, 2, "{missing:?}");
    assert_eq!(missing.json()["code"], "NOT_FOUND");

    let not_enrolled = rt.run(&["--json", "destination", "prefer", "lab1", "managed"]);
    assert_eq!(not_enrolled.code, 4, "{not_enrolled:?}");
    assert_eq!(
        not_enrolled.json()["data"]["error"]["reason"],
        "pair_not_enrolled"
    );
    let human = rt.run(&["destination", "prefer", "lab1", "managed"]);
    assert_eq!(human.code, 4, "{human:?}");
    assert!(
        human
            .stdout
            .contains("heimdall enroll lab1 --account deploy"),
        "{human:?}"
    );
    assert!(
        human.stderr.contains("reason: pair_not_enrolled"),
        "{human:?}"
    );

    // `existing` on a pair with no stored preference changes nothing.
    let noop = rt.run(&["--json", "destination", "prefer", "lab1", "existing"]);
    assert_eq!(noop.code, 0, "{noop:?}");
    assert_eq!(noop.json()["data"]["changed"], false);

    // A verified enrollment for dst-lab1/deploy (the parent's synthetic record).
    {
        let store = Store::open(&rt.db(), Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                tx.insert_issuer(&heimdall_store::IssuerRecord {
                    ca_fingerprint: ca(),
                    public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIfixture0".into(),
                    state: CaState::Active,
                    store_kind: StoreKind::LinuxSecretService,
                    backup_sha256: "00".repeat(32),
                    backup_created_at: t0(),
                    restored_without_log: false,
                    created_at: t0(),
                    retired_at: None,
                })?;
                tx.seed_enrollment(&enrollment(1, EnrollmentState::Verified))
            })
            .unwrap();
    }
    let managed = rt.run(&["--json", "destination", "prefer", "lab1", "managed"]);
    assert_eq!(managed.code, 0, "{managed:?}");
    assert_envelope_shape(&managed.json());
    assert_eq!(managed.json()["data"]["mechanism"], "managed_certificate");
    assert_eq!(managed.json()["data"]["changed"], true);
    assert_eq!(managed.json()["data"]["projection"]["state"], "pending");
    let listing = rt.run(&["--json", "destination", "show", "lab1"]);
    assert_eq!(
        listing.json()["data"]["preference"]["mechanism"],
        "managed_certificate",
        "{listing:?}"
    );
    // ⟨ADR-0008 §17.27 item 9; W5-R06⟩ The runtime's list shape is `items[]`: lab1/deploy
    // is in no saved policy, so its managed preference's connection policy cannot be
    // computed (no `connection_policy`), and both `destination list` and `inspect
    // destinations` say it is unknown, from that real answer.
    let inspected = rt.run(&["--json", "inspect", "destinations"]);
    assert_eq!(inspected.code, 0, "{inspected:?}");
    let items = inspected.json()["data"]["items"].clone();
    let lab1 = items
        .as_array()
        .unwrap_or_else(|| panic!("the runtime lists `items`: {inspected:?}"))
        .iter()
        .find(|d| d["alias"] == "lab1")
        .cloned()
        .unwrap();
    assert_eq!(
        lab1["preference"]["mechanism"], "managed_certificate",
        "{lab1}"
    );
    assert!(
        lab1["preference"].get("connection_policy").is_none(),
        "{lab1}"
    );
    for argv in [&["destination", "list"][..], &["inspect", "destinations"]] {
        let human = rt.run(argv);
        assert_eq!(human.code, 0, "{argv:?}: {human:?}");
        assert_eq!(
            human
                .stdout
                .matches(
                    "lab1: connection policy unknown (the runtime reports none for this pair)."
                )
                .count(),
            1,
            "{argv:?}: {human:?}"
        );
        assert!(
            !human.stdout.contains("seen: connection policy"),
            "{human:?}"
        );
    }
    let again = rt.run(&["destination", "prefer", "lab1", "managed"]);
    assert_eq!(again.code, 0, "{again:?}");
    assert!(again.stdout.contains("unchanged"), "{again:?}");
    let back = rt.run(&["destination", "prefer", "lab1", "existing"]);
    assert_eq!(back.code, 0, "{back:?}");
    assert!(
        back.stdout
            .contains("lab1: preference is existing (changed)."),
        "{back:?}"
    );
    assert!(back.stdout.contains("heimdall setup apply"), "{back:?}");
}

/// A fixture public key file (generated per run, never committed).
fn scratch_key(rt: &Rt) -> PathBuf {
    let key = heimdall_testkit::agent::FixtureKey::generate_many(1);
    let path = rt.scratch.path().join("fixture.pub");
    std::fs::write(&path, format!("{}\n", key[0].public_line_without_comment())).unwrap();
    path
}

// ---- help and discovery goldens ------------------------------------------------------------

/// Every M03 command line whose `--help` is a golden, and the file stem it is stored under
/// (`tests/contracts/golden/cli-help/<stem>.txt`).
const HELP_LINES: &[(&str, &[&str])] = &[
    ("top-level", &[]),
    ("issuer", &["issuer"]),
    ("issuer-init", &["issuer", "init"]),
    ("issuer-status", &["issuer", "status"]),
    ("issuer-unlock", &["issuer", "unlock"]),
    ("issuer-rotate", &["issuer", "rotate"]),
    ("issuer-rotate-begin", &["issuer", "rotate", "begin"]),
    ("issuer-retire", &["issuer", "retire"]),
    ("issuer-restore", &["issuer", "restore"]),
    ("issuer-bundle", &["issuer", "bundle"]),
    ("enroll", &["enroll"]),
    ("enroll-status", &["enroll", "status"]),
    ("enroll-verify", &["enroll", "verify"]),
    ("enroll-remove", &["enroll", "remove"]),
    ("enroll-reconcile", &["enroll", "reconcile"]),
    ("enroll-abandon", &["enroll", "abandon"]),
    ("connections", &["connections"]),
    ("connections-close", &["connections", "close"]),
    ("access", &["access"]),
    ("access-ensure", &["access", "ensure"]),
    ("access-lock-behavior", &["access", "lock-behavior"]),
    ("access-connection-policy", &["access", "connection-policy"]),
    ("destination", &["destination"]),
    ("destination-prefer", &["destination", "prefer"]),
];

/// `heimdall <line> --help` with a cleared environment (no `HEIMDALL_HOME`: clap prints an
/// `env` argument's value, so a path would leak into the text).
fn help_of(line: &[&str]) -> String {
    let out = std::process::Command::new(bin())
        .args(line)
        .arg("--help")
        .env_clear()
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0), "{line:?} --help");
    assert!(out.stderr.is_empty(), "{line:?}: stderr on --help");
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains('\u{1b}'), "{line:?}: no ANSI in piped help");
    text
}

/// m03-plan U12 "help and discovery goldens": the `--help` of each M03 command line
/// (`issuer *`, `enroll *`, `connections *`, `access lock-behavior|connection-policy`,
/// `destination prefer`, and `access ensure` for `--strict`) equals its golden under
/// `tests/contracts/golden/cli-help/` (`HM_UPDATE_GOLDENS=1` rewrites them; an absent or
/// differing file otherwise fails). Discovery: the top-level help lists `issuer`, `enroll`
/// and `connections`, and does not list `internal`, whose own help is also reachable only
/// by name; every help names the command it is for.
#[test]
fn m03_help_and_discovery_goldens() {
    let dir = heimdall_testkit::repo::repo_path("tests/contracts/golden/cli-help");
    let update = std::env::var_os("HM_UPDATE_GOLDENS").is_some_and(|v| v == "1");
    if update {
        std::fs::create_dir_all(&dir).unwrap();
    }
    // Every golden is checked; the failure lists every mismatch, not the first.
    let mut mismatches: Vec<String> = Vec::new();
    for (stem, line) in HELP_LINES {
        let text = help_of(line);
        let path = dir.join(format!("{stem}.txt"));
        if update {
            std::fs::write(&path, &text).unwrap();
            continue;
        }
        let golden = match std::fs::read_to_string(&path) {
            Ok(g) => g,
            Err(e) => {
                mismatches.push(format!(
                    "{}: {e} (HM_UPDATE_GOLDENS=1 writes it)",
                    path.display()
                ));
                continue;
            }
        };
        if text != golden {
            let first = text
                .lines()
                .zip(golden.lines())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| text.lines().count().min(golden.lines().count()));
            mismatches.push(format!(
                "{stem}: help changed at line {} (got {:?}, golden {:?})",
                first + 1,
                text.lines().nth(first).unwrap_or(""),
                golden.lines().nth(first).unwrap_or("")
            ));
        }
        if !line.is_empty() && !text.contains(&format!("heimdall {}", line.join(" "))) {
            mismatches.push(format!(
                "{stem}: the usage line does not name `heimdall {}`",
                line.join(" ")
            ));
        }
        if text.contains("heimdall.exe") {
            mismatches.push(format!("{stem}: the usage names the file `heimdall.exe`"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} help goldens differ ({} mismatches; HM_UPDATE_GOLDENS=1 rewrites them):\n{}",
        mismatches
            .iter()
            .filter_map(|m| m.split(':').next())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        HELP_LINES.len(),
        mismatches.len(),
        mismatches.join("\n")
    );
    // No stale goldens: every file in the directory is one of ours.
    if !update {
        let mut found: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        found.sort();
        let mut want: Vec<String> = HELP_LINES.iter().map(|(s, _)| format!("{s}.txt")).collect();
        want.sort();
        assert_eq!(found, want, "stale or missing help goldens");
    }

    // Discovery.
    let top = help_of(&[]);
    for listed in ["issuer", "enroll", "connections"] {
        assert!(
            top.lines()
                .any(|l| l.trim_start().starts_with(&format!("{listed} "))),
            "{listed} is not listed in the top-level help"
        );
    }
    assert!(
        !top.lines().any(|l| l.trim_start().starts_with("internal")),
        "`internal` is hidden"
    );
    // Each M03 command's help leads with what it does (never empty).
    for (stem, line) in HELP_LINES {
        let first = help_of(line);
        assert!(
            !first.lines().next().unwrap_or("").trim().is_empty(),
            "{stem}"
        );
    }
}

/// ⟨M03 wave 5, worker R⟩ `heimdall internal session-lock-state` (m03-plan §4.4 step 4,
/// §5 item 24): the hidden read-only query answers one `OK` envelope naming the state the
/// runtime's source reads, its source and its signal, and starts no runtime, creates no
/// home and writes nothing:
/// * under the test configuration (`HEIMDALL_TEST_SESSION_LOCK`) it is the fake source's
///   reading of the state file: `locked`, `unlocked`, `unavailable` for a missing file,
///   `unknown` for an unrecognized word (never a guess);
/// * a relative state-file path is a usage error (2) before anything is read;
/// * without it, the platform source's first reading (whatever this host reads; one of the
///   four states, with the platform's signal or `none`).
#[test]
fn internal_session_lock_state_reads_the_source_read_only() {
    let scratch = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(scratch.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let home = scratch.path().join("home");
    let account = scratch.path().join("account");
    let file = scratch.path().join("lock-state");
    let path = file.to_string_lossy().into_owned();
    let query = |env: &[(&str, &str)]| {
        run(
            &home,
            &account,
            &["--json", "internal", "session-lock-state"],
            env,
        )
    };
    for (word, state) in [
        (Some("locked\n"), "locked"),
        (Some("unlocked"), "unlocked"),
        (Some("sideways"), "unknown"),
        (None, "unavailable"),
    ] {
        match word {
            Some(w) => std::fs::write(&file, w).unwrap(),
            None => {
                let _ = std::fs::remove_file(&file);
            }
        }
        let out = query(&[("HEIMDALL_TEST_SESSION_LOCK", &path)]);
        assert_eq!(out.code, 0, "{word:?}: {out:?}");
        let env = out.json();
        assert_envelope_shape(&env);
        assert_eq!(env["code"], "OK", "{out:?}");
        assert_eq!(env["data"]["state"], state, "{word:?}: {out:?}");
        assert_eq!(env["data"]["source"], "test_configuration", "{out:?}");
        assert_eq!(env["data"]["signal"], "test_state_file", "{out:?}");
    }
    let relative = query(&[("HEIMDALL_TEST_SESSION_LOCK", "lock-state")]);
    assert_eq!(relative.code, 2, "{relative:?}");
    assert!(
        relative.message().contains("HEIMDALL_TEST_SESSION_LOCK"),
        "{relative:?}"
    );

    let platform = query(&[]);
    assert_eq!(platform.code, 0, "{platform:?}");
    let env = platform.json();
    assert_envelope_shape(&env);
    assert_eq!(env["data"]["source"], "platform", "{platform:?}");
    let state = env["data"]["state"].as_str().unwrap();
    assert!(
        ["locked", "unlocked", "unknown", "unavailable"].contains(&state),
        "{platform:?}"
    );
    let signal = env["data"]["signal"].as_str().unwrap();
    let expected = if state == "unavailable" {
        "none"
    } else if cfg!(target_os = "macos") {
        "macos_screen_lock"
    } else if cfg!(windows) {
        "windows_session"
    } else if cfg!(target_os = "linux") {
        "linux_logind"
    } else {
        "none"
    };
    assert_eq!(signal, expected, "{platform:?}");
    #[allow(clippy::print_stderr)] // an observation for the evidence record
    {
        eprintln!(
            "m03 observation: internal session-lock-state platform state={state} signal={signal}"
        );
    }

    // Read-only: no home, no state, nothing written next to the state file.
    assert!(!home.exists(), "the query created the Heimdall home");
    let left: Vec<_> = std::fs::read_dir(scratch.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "the query wrote {left:?}");
}

/// ⟨M03 wave 5, worker R⟩ U9-Q3 (a) through the real binary: `access lock-behavior
/// revoke-on-lock` (a usable fake signal), a `revoke_on_lock` grant's `access ensure`
/// and `inspect capabilities` carry `signal_unverified` exactly where the runtime's
/// signal is logind (Linux, until B11) and nothing elsewhere; the CLI prints the
/// warning verbatim in human mode. On macOS and Windows this checks the absence; the
/// Linux half runs natively on Linux.
#[test]
fn lock_behavior_results_labelled_signal_unverified_on_linux_only() {
    let rt = Rt::new("unlocked");
    let labelled = |out: &Out| {
        out.json()["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["code"] == "signal_unverified")
    };
    let linux = cfg!(target_os = "linux");
    let set = rt.run(&[
        "--json",
        "access",
        "lock-behavior",
        "--policy",
        "pol",
        "revoke-on-lock",
    ]);
    assert_eq!(set.code, 0, "{set:?}");
    assert_eq!(labelled(&set), linux, "{set:?}");
    let ensured = rt.ensure("lbl", &[]);
    assert_eq!(ensured.code, 0, "{ensured:?}");
    assert_eq!(labelled(&ensured), linux, "{ensured:?}");
    let caps = rt.run(&["--json", "inspect", "capabilities"]);
    assert_eq!(caps.code, 0, "{caps:?}");
    assert_eq!(labelled(&caps), linux, "{caps:?}");
    let human = rt.run(&[
        "access",
        "lock-behavior",
        "--policy",
        "pol",
        "revoke-on-lock",
    ]);
    assert_eq!(human.code, 0, "{human:?}");
    assert_eq!(
        human.stderr.contains("warning: signal_unverified"),
        linux,
        "{human:?}"
    );
}
