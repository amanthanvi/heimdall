//! ⟨M06 W5⟩ The fixture driver of the **Windows controller journey** (ADR-0012 §2.6, the
//! 2026-11-22 paragraph; m06-plan §3 "Windows controller rows"). Cargo test target
//! `e2e_windows_controller_m06`, hosted by `heimdall`.
//!
//! The journey itself is `tests/native/m06/run-windows-controller.ps1`: a Windows controller
//! (the real `heimdall.exe`, K_mgmt in its DPAPI store under a scratch Heimdall home, the
//! K_mgmt session agent on its named pipe, the in-box OpenSSH) drives a fixture Linux runner
//! in scratch directories inside the PC's existing WSL distribution (none is created or
//! removed) through the product CLI. That script prints the
//! `m06 observation:` lines. This target holds only the three things a script cannot do, as
//! `#[ignore]`d entries the script runs by exact name with `--ignored`:
//!
//! * [`seed_controller`] (any platform; run on Windows): the controller installation's
//!   fixture state, written while no runtime runs, as `exit_m06/world.rs` seeds it: its own
//!   environment, `runner-profile` holding the journey's pair, the runner's destination with
//!   a **verified enrollment** naming the management sshd and its host key (the catalog pin
//!   `environment add` requires), and an issuer whose CA key is in the scratch secret
//!   store. **No K_mgmt and no record of the runner**: `environment add` makes both.
//! * [`environment_add`] (any platform; run on Windows): `heimdall environment add` on a
//!   pseudo-terminal (`heimdall_testkit::console`: ConPTY on Windows), typing `yes` at the
//!   runner's confirmation, which the bootstrap session shows on that terminal.
//! * [`seed_runner`] (Unix; run inside the distribution from the Linux build of this
//!   target): the runner's catalog as its owner set it up (the profile, the standing policy,
//!   the destination), after the bootstrap created the runner and before its runtime starts.
//!
//! Each reads its inputs from `HM_M06J_*` variables and writes one `key=value` facts file
//! (public facts only: IDs, a public key line, a fingerprint, an exit code). Without the
//! variables an entry fails with the missing name; an ordinary test run never runs them
//! (they are ignored). The parsing they share is tested here on every platform.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    missing_docs
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use heimdall_contract::ids::{
    AccountName, DestinationId, EnrollmentId, EnvironmentId, IdentityId, ProfileId,
};
use heimdall_contract::request::AccessPairRef;
use heimdall_credential::cert::SecretCaKey;
use heimdall_domain::catalog::{DestinationDefinition, DestinationRecord};
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentForm, EnrollmentRecord, EnrollmentState,
    ExistingAccessRecord, NoProxy, RegistryCanonical, RegistryRef, RegistryResolvedBy, marker_for,
};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{Capability, Scope};
use heimdall_domain::time::Clock as _;
use heimdall_issuer::store::SecretStore as _;
use heimdall_store::{NoFaults, Store};

/// The destination the runner's management sshd is recorded under on the controller.
const RUNNER_DESTINATION: &str = "runner1";
/// The onward destination of the journey's pair, on both installations.
const ONWARD_DESTINATION: &str = "h1";
/// The profile of the journey's pair, on both installations.
const PROFILE: &str = "runner-profile";
/// The scratch secret store's directory under the state directory
/// (`HEIMDALL_TEST_SECRET_STORE=scratch`).
const SCRATCH_STORE_DIR: &str = "scratch-secret-store";

/// The end of the runner's typed confirmation (`remote init`), as the bootstrap session
/// shows it on the controller's terminal.
const CONFIRMATION: &str = "Type yes to continue";

/// The end of the bootstrap's offer to start the runner's runtime (`heimdall`'s
/// `runtime_start_offer`).
const RUNTIME_OFFER: &str = "Type yes to start it";

/// A required input, or a panic naming it.
fn input(env: &BTreeMap<String, String>, name: &str) -> String {
    env.get(name)
        .filter(|v| !v.is_empty())
        .cloned()
        .unwrap_or_else(|| panic!("the journey driver needs {name}"))
}

/// This process's `HM_M06J_*` variables.
fn inputs() -> BTreeMap<String, String> {
    std::env::vars()
        .filter(|(k, _)| k.starts_with("HM_M06J_"))
        .collect()
}

/// `<type> <base64>` of an OpenSSH public key line, without its comment; `None` for
/// anything that is not one Ed25519 key line (the fixture sshds have Ed25519 host keys).
fn ed25519_key(line: &str) -> Option<(String, String)> {
    let mut words = line.split_ascii_whitespace();
    let (kind, blob) = (words.next()?, words.next()?);
    let plain = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-'))
    };
    (kind == "ssh-ed25519" && plain(blob) && blob.starts_with("AAAAC3NzaC1lZDI1NTE5"))
        .then(|| (kind.to_owned(), blob.to_owned()))
}

/// A facts file's text: one `key=value` line per fact, sorted, values on one line.
fn facts_text(facts: &BTreeMap<&str, String>) -> String {
    facts
        .iter()
        .map(|(k, v)| format!("{k}={}\n", v.replace(['\r', '\n'], " ")))
        .collect()
}

fn write_facts(env: &BTreeMap<String, String>, facts: &BTreeMap<&str, String>) {
    let out = PathBuf::from(input(env, "HM_M06J_FACTS_OUT"));
    std::fs::write(out, facts_text(facts)).unwrap();
}

fn random16() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    heimdall_credential::vault::SystemRng::fill(&mut bytes).unwrap();
    bytes
}

fn open_store(home: &Path) -> Store {
    let paths = heimdall_runtime::Paths::under(home);
    paths.ensure().unwrap();
    Store::open(
        &paths
            .state_dir
            .join(heimdall_runtime::service::STATE_DB_FILE),
        Arc::new(NoFaults),
    )
    .unwrap()
}

fn journey_scope(account: &AccountName) -> (AccessPairRef, Scope) {
    let pair = AccessPairRef {
        destination: DestinationId::parse(ONWARD_DESTINATION).unwrap(),
        account: account.clone(),
    };
    let scope = Scope {
        pairs: [pair.clone()].into_iter().collect(),
        capabilities: [Capability::SshAuthentication].into_iter().collect(),
    };
    (pair, scope)
}

/// The controller installation's fixture state (module docs). Inputs: `HM_M06J_HOME` (the
/// controller's scratch Heimdall home), `HM_M06J_ACCOUNT` (the runner account),
/// `HM_M06J_ALIAS` (the ssh alias of the existing access, in the scratch configuration),
/// `HM_M06J_MGMT_HOST`, `HM_M06J_MGMT_PORT`, `HM_M06J_MGMT_HOST_KEY` (the management sshd's
/// Ed25519 host key line), `HM_M06J_FACTS_OUT`. Facts: `ca_public_key`, `ca_fingerprint`,
/// `principal`, `controller_environment`.
#[test]
#[ignore = "run by tests/native/m06/run-windows-controller.ps1 with its HM_M06J_* inputs"]
fn seed_controller() {
    let env = inputs();
    let home = PathBuf::from(input(&env, "HM_M06J_HOME"));
    let account = AccountName::parse(&input(&env, "HM_M06J_ACCOUNT")).unwrap();
    let alias = input(&env, "HM_M06J_ALIAS");
    let host = input(&env, "HM_M06J_MGMT_HOST");
    let port: u16 = input(&env, "HM_M06J_MGMT_PORT").parse().unwrap();
    let host_key_line = input(&env, "HM_M06J_MGMT_HOST_KEY");
    let (algorithm, key) = ed25519_key(&host_key_line).expect("an Ed25519 host key line");
    let fingerprint = heimdall_credential::mgmt::openssh_fingerprint(&format!("{algorithm} {key}"))
        .expect("a host key fingerprint");
    let now = heimdall_runtime::platform::SystemClock.wall();
    let ca = SecretCaKey::generate().unwrap();
    let ca_fingerprint = ca.fingerprint().unwrap();
    let ca_public = ca.public_openssh().unwrap();
    let (pair, scope) = journey_scope(&account);
    let runner = DestinationId::parse(RUNNER_DESTINATION).unwrap();
    let own = EnvironmentId::from_random_bytes(random16());

    // K_ca in the scratch secret store the debug build's issuer child reads.
    let paths = heimdall_runtime::Paths::under(&home);
    paths.ensure().unwrap();
    let secrets = paths.state_dir.join(SCRATCH_STORE_DIR);
    std::fs::create_dir_all(&secrets).unwrap();
    heimdall_testkit::scratch_store::ScratchSecretStore::new(secrets)
        .put(&ca_fingerprint, &ca)
        .unwrap();

    let id = EnrollmentId::from_random_bytes(random16());
    let enrollment = EnrollmentRecord {
        marker: marker_for(&id),
        id,
        destination: runner.clone(),
        account: account.clone(),
        ca_fingerprint: ca_fingerprint.clone(),
        form: EnrollmentForm::Account,
        registry: RegistryRef {
            path_display: "~/.ssh/authorized_keys".into(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        registry_canonical: RegistryCanonical {
            path: None,
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        line_sha256: "ab".repeat(32),
        target: ApprovedTarget {
            hostname: host,
            port,
            user: account.clone(),
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm,
                key,
                fingerprint: fingerprint.as_str().to_owned(),
            },
        },
        existing_access: ExistingAccessRecord {
            identity: IdentityId::from_random_bytes(random16()),
            endpoint: None,
            public_key_file: None,
        },
        hold: None,
        removal_origin: None,
        late_write: None,
        state: EnrollmentState::Verified,
        verified_at: Some(now),
        evidence: None,
        created_at: now,
        updated_at: now,
    };
    open_store(&home)
        .transaction(|tx| {
            tx.init_self_environment(&own)?;
            tx.upsert_profile(&ProfileDefinition {
                id: ProfileId::parse(PROFILE).unwrap(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_destination(&DestinationRecord {
                id: runner.clone(),
                alias: alias.clone(),
                revision: 1,
                definition: DestinationDefinition::Observed,
                label: None,
                updated_at: now,
            })?;
            tx.insert_issuer(&heimdall_store::IssuerRecord {
                ca_fingerprint: ca_fingerprint.clone(),
                public_key: ca_public.clone(),
                state: heimdall_contract::issuer::CaState::Active,
                // The scratch store stands for the platform store; the kind is a label here.
                store_kind: heimdall_contract::issuer::StoreKind::LinuxSecretService,
                backup_sha256: "ab".repeat(32),
                backup_created_at: now,
                restored_without_log: false,
                created_at: now,
                retired_at: None,
            })?;
            tx.seed_enrollment(&enrollment)
        })
        .unwrap();
    drop(ca);
    let facts: BTreeMap<&str, String> = [
        ("ca_public_key", ca_public.trim().to_owned()),
        ("ca_fingerprint", ca_fingerprint.as_str().to_owned()),
        ("principal", heimdall_domain::issuance::principal_for(&pair)),
        ("controller_environment", own.as_str().to_owned()),
    ]
    .into();
    write_facts(&env, &facts);
}

/// `heimdall --json --home <home> environment add …` on a pseudo-terminal (module docs),
/// typing `yes` at the runner's confirmation ([`CONFIRMATION`]). Inputs: `HM_M06J_BIN` (the
/// `heimdall` under test), `HM_M06J_HOME`, `HM_M06J_ACCOUNT_HOME` (the scratch account
/// home: `HOME` and `HEIMDALL_TEST_SSH_HOME`), `HM_M06J_ACCOUNT`, `HM_M06J_RUNNER_PROGRAM`,
/// `HM_M06J_RUNNER_HOME`, `HM_M06J_RUNNER_SHA256`, `HM_M06J_PATH` (the `PATH` the command
/// gets: the directory of the OpenSSH client), `HM_M06J_FACTS_OUT`, optionally
/// `HM_M06J_SSH_STDERR_FILE` (⟨`w5v`⟩ passed on as `HEIMDALL_TEST_SSH_STDERR_FILE`), and off Windows
/// `HM_M06J_MGMT_FIXTURE` and `HM_M06J_IROH_FIXTURE` (the two fixture key stores; both
/// required there, see [`fixture_stores`]). Facts: `exit`, `code`, `reason`, `message`,
/// `envelope` (`present` or `absent`), `error_fields` (its error's keys, or `none`),
/// `environment`, `client`, `prompted`, `runtime_offer` (`declined`, `accepted` or
/// `not_offered`; the answer is `HM_M06J_RUNTIME_OFFER`, `no` when unset) and
/// `runtime_stated` ([`runtime_stated`]). It asserts nothing about the outcome: the script
/// judges the facts, so a refusal is reported with its code.
#[test]
#[ignore = "run by tests/native/m06/run-windows-controller.ps1 with its HM_M06J_* inputs"]
fn environment_add() {
    let env = inputs();
    let account_home = input(&env, "HM_M06J_ACCOUNT_HOME");
    let home = input(&env, "HM_M06J_HOME");
    let mut command = heimdall_testkit::console::TerminalCommand::new(input(&env, "HM_M06J_BIN"))
        .arg("--json")
        .arg("--home")
        .arg(&home)
        .args([
            "environment",
            "add",
            "--destination",
            RUNNER_DESTINATION,
            "--account",
            &input(&env, "HM_M06J_ACCOUNT"),
            "--runner-program",
            &input(&env, "HM_M06J_RUNNER_PROGRAM"),
            "--runner-home",
            &input(&env, "HM_M06J_RUNNER_HOME"),
            "--runner-sha256",
            &input(&env, "HM_M06J_RUNNER_SHA256"),
        ])
        .size(400, 50)
        .env("PATH", input(&env, "HM_M06J_PATH"))
        .env("HOME", &account_home)
        .env("USERPROFILE", &account_home)
        .env("HEIMDALL_HOME", &home)
        .env("HEIMDALL_TEST_SSH_HOME", &account_home)
        .env("HEIMDALL_TEST_TIME_SYNC", "synchronized")
        .env("HEIMDALL_TEST_SECRET_STORE", "scratch");
    // The key stores. On Windows K_mgmt is the product's own: with an explicit Heimdall home
    // the DPAPI blob lives under that scratch home, which is the journey's subject. Anywhere
    // else the product stores of K_mgmt and K_iroh are the account's real key stores (the
    // login keychain, the Secret Service), which no test may touch: BOTH fixture stores are
    // required there (RULES "KEY STORES"; `environment add` reads K_iroh for the endpoint
    // it announces), and without them nothing is started.
    if cfg!(not(windows)) {
        let (mgmt, iroh) = fixture_stores(&env);
        command = command
            .env("HEIMDALL_TEST_MGMT_STORE", format!("fixture-file:{mgmt}"))
            .env("HEIMDALL_TEST_IROH_KEY_STORE", iroh);
    }
    // ⟨M06 W5 `w5v`, PC job 42⟩ The bootstrap's `ssh` messages, when the journey asks for them
    // (`HM_M06J_SSH_STDERR_FILE`, an absolute scratch file): the debug build's
    // `HEIMDALL_TEST_SSH_STDERR_FILE`. The script protects what it copies out.
    if let Some(file) = env.get("HM_M06J_SSH_STDERR_FILE").filter(|v| !v.is_empty()) {
        command = command.env("HEIMDALL_TEST_SSH_STDERR_FILE", file);
    }
    // The platform's own directories, which the DPAPI store and the client need on Windows.
    // ⟨M06 W5 `w5v`, PC job 44⟩ `ProgramData` included: the in-box `ssh.exe` that `heimdall`
    // starts inherits this environment, and Win32-OpenSSH exits 255 without a word when it
    // is unset (`init_prog_paths`, before its standard error exists).
    for name in [
        "LOCALAPPDATA",
        "APPDATA",
        "TEMP",
        "TMP",
        "USERNAME",
        "ProgramData",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command = command.env(name, value);
        }
    }
    let mut terminal = command.spawn().expect("a pseudo-terminal");
    let prompted = terminal
        .expect(CONFIRMATION, Duration::from_secs(120))
        .is_ok();
    if prompted {
        std::thread::sleep(Duration::from_millis(300));
        terminal.send(b"yes\r").unwrap();
    }
    // ⟨M06 W5k; ADR-0012 §2.6, the 2026-11-22 bullets⟩ The bootstrap's offer to start the
    // runner's runtime in this same session, when it does not run. The journey answers
    // what `HM_M06J_RUNTIME_OFFER` says (`yes` or `no`; `no` when unset): its fixture runner
    // is seeded while no runtime runs and its runtime needs the fixture's own test
    // configuration, so the journey declines and starts it itself, as a stated step.
    let answer = env
        .get("HM_M06J_RUNTIME_OFFER")
        .map_or("no", String::as_str)
        .to_owned();
    assert!(
        answer == "yes" || answer == "no",
        "HM_M06J_RUNTIME_OFFER is yes or no"
    );
    let offered = prompted
        && terminal
            .expect(RUNTIME_OFFER, Duration::from_secs(120))
            .is_ok();
    if offered {
        std::thread::sleep(Duration::from_millis(300));
        terminal.send(format!("{answer}\r").as_bytes()).unwrap();
    }
    let exit = terminal.wait(Duration::from_secs(180));
    let text = terminal.text();
    heimdall_testkit::assert_no_canary(&text);
    let envelope = last_envelope(&text);
    let field = |path: &[&str]| -> String {
        let mut at = envelope.as_ref();
        for key in path {
            at = at.and_then(|v| v.get(key));
        }
        at.and_then(serde_json::Value::as_str)
            .unwrap_or("none")
            .to_owned()
    };
    let facts: BTreeMap<&str, String> = [
        ("exit", exit.map_or("none".to_owned(), |c| c.to_string())),
        ("code", field(&["code"])),
        ("reason", field(&["data", "error", "reason"])),
        ("message", field(&["data", "error", "message"])),
        // ⟨`w5s`, PC job 38 diagnostics⟩ Whether the transcript held an answer at all, and
        // the keys of its error, so a step that fails before its code is checked still says
        // what came back (the script protects every value it logs).
        (
            "envelope",
            if envelope.is_some() {
                "present"
            } else {
                "absent"
            }
            .to_owned(),
        ),
        (
            "error_fields",
            envelope
                .as_ref()
                .and_then(|v| v.get("data")?.get("error")?.as_object().cloned())
                .map_or("none".to_owned(), |m| {
                    m.keys().cloned().collect::<Vec<_>>().join(",")
                }),
        ),
        ("environment", field(&["data", "environment"])),
        ("client", field(&["data", "client"])),
        ("prompted", prompted.to_string()),
        (
            "runtime_offer",
            match (offered, answer.as_str()) {
                (false, _) => "not_offered",
                (true, "yes") => "accepted",
                (true, _) => "declined",
            }
            .to_owned(),
        ),
        ("runtime_stated", runtime_stated(&text).to_owned()),
    ]
    .into();
    write_facts(&env, &facts);
}

/// What the bootstrap session said about the runner's runtime (its own sentences, read
/// from the terminal's text with its line breaks removed): `started` (an accepted offer),
/// `not_started` (a declined one, with the next step), `running` (it ran already),
/// `not_running` (said, and the session ended before an answer), or `none`.
fn runtime_stated(transcript: &str) -> &'static str {
    let flat: String = transcript.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.contains("runtime is running on this installation (started now)") {
        "started"
    } else if flat.contains("The runner's runtime was not started. Next step:") {
        "not_started"
    } else if flat.contains("The runner's runtime is running on this installation") {
        "running"
    } else if flat.contains("The runner's runtime is NOT running") {
        "not_running"
    } else {
        "none"
    }
}

/// The two fixture key stores a journey command needs off Windows: `HM_M06J_MGMT_FIXTURE`
/// (an absolute scratch file, the fixture K_mgmt store) and `HM_M06J_IROH_FIXTURE` (an
/// absolute scratch directory, the fixture K_iroh store; created owner-only here when it
/// does not exist). Panics, before anything is started, when either is missing, relative,
/// or the same path.
fn fixture_stores(env: &BTreeMap<String, String>) -> (String, String) {
    let mgmt = input(env, "HM_M06J_MGMT_FIXTURE");
    let iroh = input(env, "HM_M06J_IROH_FIXTURE");
    for (name, value) in [
        ("HM_M06J_MGMT_FIXTURE", &mgmt),
        ("HM_M06J_IROH_FIXTURE", &iroh),
    ] {
        assert!(
            Path::new(value).is_absolute(),
            "the journey driver needs an absolute {name}"
        );
    }
    assert_ne!(mgmt, iroh, "the two fixture stores are separate paths");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
        let dir = Path::new(&iroh);
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .expect("the fixture K_iroh store directory");
        }
        let mode = std::fs::metadata(dir)
            .expect("the fixture K_iroh store directory")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o077,
            0,
            "HM_M06J_IROH_FIXTURE must be an owner-only directory"
        );
    }
    (mgmt, iroh)
}

/// The last JSON envelope a terminal transcript holds (the command's `--json` answer after
/// the bootstrap session's own lines): the last line that parses as an object with a
/// `code`.
fn last_envelope(transcript: &str) -> Option<serde_json::Value> {
    transcript.lines().rev().find_map(|line| {
        let start = line.find('{')?;
        let value: serde_json::Value = serde_json::from_str(line[start..].trim()).ok()?;
        value.get("code").is_some().then_some(value)
    })
}

/// The runner's catalog as its owner set it up (module docs; `exit_m06/world.rs`
/// `seed_runner_catalog_with`), written while no runtime runs. Inputs: `HM_M06J_HOME` (the
/// runner's Heimdall home), `HM_M06J_ACCOUNT`, `HM_M06J_FACTS_OUT`. Facts:
/// `runner_environment`.
#[cfg(unix)]
#[test]
#[ignore = "run inside the journey's distribution with its HM_M06J_* inputs"]
fn seed_runner() {
    use heimdall_contract::ids::PolicyId;
    use heimdall_contract::managed::{ConnectionPolicy, LockBehavior};
    use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};

    let env = inputs();
    let home = PathBuf::from(input(&env, "HM_M06J_HOME"));
    let account = AccountName::parse(&input(&env, "HM_M06J_ACCOUNT")).unwrap();
    let (_, scope) = journey_scope(&account);
    let profile = ProfileId::parse(PROFILE).unwrap();
    let now = heimdall_runtime::platform::SystemClock.wall();
    let environment = open_store(&home)
        .transaction(|tx| {
            let own = tx.self_environment()?.expect("a bootstrapped runner");
            let mut record = tx.environment(&own)?.unwrap();
            record.permissions = heimdall_domain::environment::EnvironmentPermissions {
                automatic_activation: true,
                managed_signing: true,
                issuer_access: true,
            };
            tx.upsert_environment(&record)?;
            tx.upsert_profile(&ProfileDefinition {
                id: profile.clone(),
                revision: 1,
                scope: scope.clone(),
                label: None,
            })?;
            tx.upsert_policy(
                &StandingPolicy {
                    id: PolicyId::parse("runner-pol").unwrap(),
                    revision: PolicyRevision(1),
                    profile: profile.clone(),
                    workspace: None,
                    scope: scope.clone(),
                    environments: [own.clone()].into_iter().collect(),
                    max_window: Duration::from_secs(4 * 3600),
                    pause: PauseState::Active,
                    cutoff_at: None,
                    source: PolicySource::SetupDefault,
                    lock_behavior: LockBehavior::Continue,
                    connection: ConnectionPolicy::default(),
                    default: false,
                },
                false,
            )?;
            tx.upsert_destination(&DestinationRecord {
                id: DestinationId::parse(ONWARD_DESTINATION).unwrap(),
                alias: ONWARD_DESTINATION.to_owned(),
                revision: 1,
                definition: DestinationDefinition::Observed,
                label: None,
                updated_at: now,
            })?;
            Ok(own)
        })
        .unwrap();
    let facts: BTreeMap<&str, String> =
        [("runner_environment", environment.as_str().to_owned())].into();
    write_facts(&env, &facts);
}

#[test]
fn host_key_lines_are_one_ed25519_key_without_its_comment() {
    let blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOVqmTNbwT7nI0Fk7RzD4mgwA0ke2pRDCgUNQ0FHb8xn";
    assert_eq!(
        ed25519_key(&format!("ssh-ed25519 {blob} fixture@host")),
        Some(("ssh-ed25519".to_owned(), blob.to_owned()))
    );
    assert_eq!(
        ed25519_key(&format!("  ssh-ed25519   {blob}  ")),
        Some(("ssh-ed25519".to_owned(), blob.to_owned()))
    );
    for bad in [
        String::new(),
        "ssh-ed25519".to_owned(),
        format!("ssh-rsa {blob}"),
        "ssh-ed25519 AAAAB3NzaC1yc2E".to_owned(),
        format!("ssh-ed25519 {blob}'"),
        format!("ssh-ed25519 {blob}$(id)"),
        format!("127.0.0.1 ssh-ed25519 {blob}"),
    ] {
        assert_eq!(ed25519_key(&bad), None, "{bad}");
    }
}

#[test]
fn facts_are_sorted_single_lines_and_a_missing_input_is_named() {
    let facts: BTreeMap<&str, String> = [
        ("exit", "0".to_owned()),
        ("code", "OK".to_owned()),
        ("note", "two\r\nlines".to_owned()),
    ]
    .into();
    assert_eq!(facts_text(&facts), "code=OK\nexit=0\nnote=two  lines\n");
    let env: BTreeMap<String, String> = [("HM_M06J_HOME".to_owned(), String::new())].into();
    let missing = std::panic::catch_unwind(|| input(&env, "HM_M06J_HOME"));
    let message = *missing.unwrap_err().downcast::<String>().unwrap();
    assert_eq!(message, "the journey driver needs HM_M06J_HOME");
}

/// ⟨RULES "KEY STORES"⟩ Off Windows `environment_add` starts nothing without BOTH fixture
/// stores: a missing, empty or relative one is named, before any process exists.
#[test]
fn the_driver_names_a_missing_fixture_key_store_before_starting_anything() {
    let scratch = heimdall_testkit::workspace::Scratch::new().unwrap();
    let mgmt = scratch.path("k_mgmt.fixture").display().to_string();
    let iroh = scratch.path("k_iroh").display().to_string();
    let refused = |pairs: &[(&str, &str)]| -> String {
        let env: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let caught = std::panic::catch_unwind(|| fixture_stores(&env)).unwrap_err();
        match caught.downcast::<String>() {
            Ok(text) => *text,
            Err(other) => (*other.downcast::<&str>().unwrap()).to_owned(),
        }
    };
    assert_eq!(
        refused(&[("HM_M06J_MGMT_FIXTURE", &mgmt)]),
        "the journey driver needs HM_M06J_IROH_FIXTURE"
    );
    assert_eq!(
        refused(&[("HM_M06J_IROH_FIXTURE", &iroh)]),
        "the journey driver needs HM_M06J_MGMT_FIXTURE"
    );
    assert!(
        refused(&[
            ("HM_M06J_MGMT_FIXTURE", &mgmt),
            ("HM_M06J_IROH_FIXTURE", "relative")
        ])
        .contains("absolute HM_M06J_IROH_FIXTURE")
    );
    assert!(!Path::new(&iroh).exists(), "a refusal creates nothing");
    let env: BTreeMap<String, String> = [
        ("HM_M06J_MGMT_FIXTURE".to_owned(), mgmt.clone()),
        ("HM_M06J_IROH_FIXTURE".to_owned(), iroh.clone()),
    ]
    .into();
    assert_eq!(fixture_stores(&env), (mgmt, iroh.clone()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&iroh).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}

#[test]
fn the_bootstrap_sessions_runtime_statement_is_read_across_line_breaks() {
    assert_eq!(
        runtime_stated("Type yes to continue: yes\n{\"code\":\"OK\"}"),
        "none"
    );
    assert_eq!(
        runtime_stated("The runner's runtime is NOT running on this\r\n installation, so"),
        "not_running"
    );
    assert_eq!(
        runtime_stated(
            "The runner's runtime is NOT running on this installation, so …\nType yes to \
             start it: no\nThe runner's runtime was not\nstarted. Next step: start it"
        ),
        "not_started"
    );
    assert_eq!(
        runtime_stated(
            "The runner's runtime is NOT running …\nThe runner's runtime is running on \
             this installation (started now)."
        ),
        "started"
    );
    assert_eq!(
        runtime_stated("The runner's runtime is running on this installation."),
        "running"
    );
}

#[test]
fn the_answer_is_the_last_envelope_of_the_transcript() {
    let transcript = "Enroll this controller as owner?\nType yes to continue: yes\n\
                      {\"note\": \"not an envelope\"}\n\
                      {\"code\":\"OK\",\"data\":{\"environment\":\"env_1\"}}\n\
                      Connection to 127.0.0.1 closed.\n";
    let envelope = last_envelope(transcript).unwrap();
    assert_eq!(envelope["data"]["environment"], "env_1");
    assert!(last_envelope("no json here\n").is_none());
    let refused =
        "x {\"code\":\"CAPABILITY_UNAVAILABLE\",\"data\":{\"error\":{\"reason\":\"r\"}}}\n";
    assert_eq!(
        last_envelope(refused).unwrap()["data"]["error"]["reason"],
        "r"
    );
}
