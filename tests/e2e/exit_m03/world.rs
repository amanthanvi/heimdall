//! The exit suite's shared scaffolding (`e2e_exit_m03` submodule): a [`World`] of a
//! scratch home, the **real binary's** CLI-started runtime and its **real**
//! `internal issuer` child, a seeded CA and verified enrollments for N disjoint pairs on
//! N servers, `setup apply` and `time confirm` typed through
//! [`heimdall_testkit::console`], fresh logins through the projection inside
//! `heimdall run` (each attributed by certificate key ID from the server log), and a
//! teardown that stops only what it started.
//!
//! **What runs for real and what is seeded** (the enrollment loop and the ceremony have
//! their own suites):
//! * real: `heimdall service run` started on demand by the CLI (the production managed
//!   wiring, signer table, endpoints, projection), its issuer child (the real binary's
//!   `internal issuer` over the run's issuer store), the catalog (`identity adopt`,
//!   `destination add`), `destination prefer … managed`, `setup apply`, `time confirm`,
//!   `access ensure|revoke`, `run`, `doctor`, `inspect`, `operation events`;
//! * seeded while the runtime is stopped: a fresh K_ca in the issuer store, its `active`
//!   CA record and store locator; per pair a `verified` account-form enrollment under that
//!   CA (its approved target the server's real route and host key, its evidence naming
//!   the local client, so the runtime's freshness rules leave it `verified`); the profile
//!   `exit` with every pair and its standing policy `exit-pol` (`continue` on lock); and,
//!   after `destination prefer`, the CA in each pair's issuing set (as E5 records it).
//!
//! **The issuer store** (m03-plan §0.2): Unix testkit's `ScratchSecretStore`
//! (`HEIMDALL_TEST_SECRET_STORE=scratch`); Windows real DPAPI in a directory under the
//! scratch Heimdall home (`product-file:<dir>`, created by `test_product::create`).
//!
//! **Servers** ([`WorldOptions::servers`]): given ones (for example
//! `heimdall_testkit::sshd::ThreeHosts`), or one `LoopbackSshd` per pair. Each server's
//! account-form registry gets the CA's `cert-authority` line for its pair's principal
//! `hm:<destination>:<account>`. On Windows the server is the harness's WSL sshd
//! (`HM_FIXTURE_SSHD_*`, its enrollment registry `HM_FIXTURE_SSHD_REGISTRY*`, its account
//! `HM_FIXTURE_SSHD_USER`), which serves one pair per test thread.
//!
//! **Isolation** (m03-plan §0.2): every process gets a cleared environment (the
//! variables below only), the scratch root as its working directory and stdin closed or
//! a terminal. Clients get only `ScratchHome::isolation_args` (`-F`, the scratch
//! known-hosts files, `BatchMode=yes`), the decoy agent at `SSH_AUTH_SOCK` and the scratch
//! `HOME`; their identity comes from the projection under test. No owner key, agent,
//! keychain, Credential Manager or `~/.ssh` is touched.
#![allow(clippy::unwrap_used, clippy::expect_used, dead_code)]

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use heimdall_contract::Timestamp;
use heimdall_contract::ids::{
    AccountName, CaFingerprint, DestinationId, EnrollmentId, EnvironmentId, IdentityId,
    OperationId, PolicyId, ProfileId,
};
use heimdall_contract::issuer::{CaState, StoreKind};
use heimdall_contract::request::Capability;
use heimdall_credential::cert::SecretCaKey;
use heimdall_domain::enrollment::{
    ApprovedHostKey, ApprovedTarget, EnrollmentEvidence, EnrollmentForm, EnrollmentRecord,
    EnrollmentState, ExistingAccessRecord, NoProxy, RegistryCanonical, RegistryRef,
    RegistryResolvedBy, marker_for,
};
use heimdall_domain::policy::{PauseState, PolicyRevision, PolicySource, StandingPolicy};
use heimdall_domain::profile::ProfileDefinition;
use heimdall_domain::scope::{AccessPair, Scope};
use heimdall_issuer::store::SecretStore as _;
use heimdall_store::{IssuerRecord, NoFaults, Store};
use heimdall_testkit::console::TerminalCommand;
use heimdall_testkit::home::{ScratchHome, find_program};
use heimdall_testkit::sshd::{LoopbackSshd, SshdConfig};
use serde_json::Value;

/// The worker's instruction-file variable ([`crate::worker`]).
pub const WORKER_ENV: &str = "HM_EXIT_M03_WORKER";

/// The profile the world creates (every pair) and its standing policy.
pub const PROFILE: &str = "exit";
/// The standing policy covering [`PROFILE`].
pub const POLICY: &str = "exit-pol";

/// The seeded policies' `max_window` unless [`WorldOptions::pair_policy_windows`] says
/// otherwise.
const DEFAULT_POLICY_WINDOW: Duration = Duration::from_secs(2 * 3600);

/// The binary under test.
pub fn bin() -> PathBuf {
    std::env::var_os("HEIMDALL_E2E_BIN")
        .filter(|p| !p.is_empty())
        .map_or_else(
            || PathBuf::from(env!("CARGO_BIN_EXE_heimdall")),
            PathBuf::from,
        )
}

/// This platform's token in the observation lines.
pub fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    }
}

/// The system OpenSSH program `name` (`ssh`, `ssh-add`, `ssh-keygen`): Unix the one the
/// CLI-started runtime resolves (`PATH=/usr/bin:/bin`), else the first on `PATH`;
/// Windows the in-box client (ADR-0004 E6).
pub fn openssh(name: &str) -> PathBuf {
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let p = PathBuf::from(root)
            .join("System32")
            .join("OpenSSH")
            .join(format!("{name}.exe"));
        if p.exists() {
            return p;
        }
    }
    #[cfg(unix)]
    for dir in ["/usr/bin", "/bin"] {
        let p = Path::new(dir).join(name);
        if p.exists() {
            return p;
        }
    }
    find_program(name).unwrap_or_else(|| panic!("blocked: no {name} client on this host"))
}

/// One finished invocation (stdout, stderr and the exit code).
#[derive(Debug, Clone)]
pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    /// The last JSON object on stdout (the envelope).
    pub fn json(&self) -> Value {
        self.stdout
            .lines()
            .rev()
            .filter_map(|l| l.trim().find('{').map(|i| l.trim()[i..].to_owned()))
            .find_map(|l| serde_json::from_str::<Value>(&l).ok())
            .unwrap_or_else(|| panic!("no envelope: {self:?}"))
    }
}

/// Every byte the binary printed during the world's life, by command (A33 scans it).
#[derive(Debug, Default)]
pub struct Transcript {
    /// `(label, bytes)`: the label names the command, never a path or secret.
    pub entries: Vec<(String, Vec<u8>)>,
}

/// One pair of the world: its server, catalog alias, destination ID and account.
#[derive(Debug)]
pub struct Pair {
    pub alias: String,
    pub destination: String,
    pub account: String,
    pub sshd: LoopbackSshd,
}

impl Pair {
    /// `<destination>:<account>`.
    pub fn pair_arg(&self) -> String {
        format!("{}:{}", self.destination, self.account)
    }

    /// The pair's managed principal.
    pub fn principal(&self) -> String {
        format!("hm:{}:{}", self.destination, self.account)
    }
}

/// How to build a [`World`].
#[derive(Debug, Default)]
pub struct WorldOptions {
    /// How many disjoint pairs (one server each). Windows: 1 (the harness serves one
    /// account-form server per test thread).
    pub pairs: usize,
    /// Servers to use instead of starting one `LoopbackSshd` per pair (their count must
    /// be `pairs`). Each must have an account-form registry.
    pub servers: Vec<LoopbackSshd>,
    /// `HEIMDALL_TEST_KEY_SEED` (raw bytes; hex-encoded into the variable).
    pub key_seed: Option<Vec<u8>>,
    /// More variables for every process the world starts (for example a canary).
    pub extra_env: Vec<(String, String)>,
    /// Also one profile per pair, `exit-<n>` (1-based), each covered by its own standing
    /// policy `exit-pol-<n>` ([`World::profile_of`]), so grants can be made on disjoint
    /// pairs (the A03 lock driver). `connect` then finds two profiles covering a pair and
    /// refuses (`no_profile_covers_destination`); `run` and `access ensure` name theirs.
    pub per_pair_profiles: bool,
    /// ⟨A03 lock driver⟩ Omit `HEIMDALL_TEST_SESSION_LOCK`, so the runtime uses the
    /// platform session-lock source (`SessionLockWiring::Platform`).
    pub platform_session_lock: bool,
    /// ⟨A03 lock driver⟩ The product configuration: no `HEIMDALL_TEST_*` variable at all
    /// (a release-profile binary refuses every one, exit 2). The issuer store is then
    /// the product kind at the location the product reads under the scratch
    /// `HEIMDALL_HOME` (Windows: DPAPI in `<hh>/state/issuer/<environment>`; other
    /// platforms: unsupported here), and the runtime's projection is the **account's
    /// own** SSH configuration (`ProjectionWiring::Account`, the account home from the
    /// account database): the caller must guard that this is not the owner's (the lock
    /// driver refuses unless the account's `.ssh` is absent or empty). After `setup
    /// apply` the scratch user configuration is a byte copy of the account's, so every
    /// client still runs with `-F <scratch>`.
    pub product: bool,
    /// ⟨A03 lock driver⟩ The `max_window` of each per-pair policy `exit-pol-<n>`, in pair
    /// order (missing entries: 2 h, as `exit-pol`).
    pub pair_policy_windows: Vec<Duration>,
    /// ⟨A03 lock driver⟩ `<hh>/config/config.toml`, written before the first command
    /// (for example a longer `session.max_window`).
    pub config_toml: Option<String>,
    /// ⟨W6-R01⟩ Own the projection's rollback from just before `setup apply`
    /// ([`World::rollback_projection`]; always on with [`WorldOptions::product`]).
    pub own_projection_rollback: bool,
    /// ⟨W6-R01, the regression only⟩ Fail right after `setup apply` (as a failing or
    /// time-limited `time confirm` would).
    pub fail_after_apply: bool,
    /// ⟨W6-R01, the regression only⟩ Make the rollback fail without running it, so the
    /// kept-recovery-state branch is exercised.
    pub fail_rollback: bool,
}

/// ⟨W6-R01⟩ Where the world's projection stands: whether a rollback is owed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Projection {
    /// No `setup apply` has been attempted (or the world does not own its rollback).
    NotApplied,
    /// `setup apply` may have run: a rollback is owed.
    MayBeApplied,
    /// Rolled back, and the restoration verified.
    RolledBack,
    /// The rollback or its verification failed; the scratch home (the projection's
    /// state and backups) is kept for recovery.
    Kept(String),
}

/// ⟨W6-R01⟩ A projection cleanup a world ran as it was dropped (for example while a
/// failed preparation unwound), for the caller to report honestly.
#[derive(Debug, Clone)]
pub struct ProjectionCleanup {
    /// `Ok(text)`: rolled back and verified; `Err(text)`: failed, recovery state kept.
    pub result: Result<String, String>,
    /// The world's scratch root (kept on failure, removed otherwise).
    pub root: PathBuf,
}

static PROJECTION_CLEANUPS: Mutex<Vec<ProjectionCleanup>> = Mutex::new(Vec::new());

/// Take the reports of the worlds dropped since the last call.
pub fn take_projection_cleanups() -> Vec<ProjectionCleanup> {
    std::mem::take(
        &mut *PROJECTION_CLEANUPS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

/// The issuer store the runtime's child selects.
#[derive(Debug, Clone)]
pub enum IssuerStore {
    /// `HEIMDALL_TEST_SECRET_STORE=scratch` (`<home>/state/scratch-secret-store`).
    Scratch(PathBuf),
    /// `product-file:<dir>`: the DPAPI directory under the scratch Heimdall home.
    ProductFile(PathBuf),
    /// ⟨A03 lock driver⟩ No test variable: the product store at the product's own
    /// location under the scratch Heimdall home ([`WorldOptions::product`]).
    Product(PathBuf),
}

impl IssuerStore {
    /// Its directory.
    pub fn dir(&self) -> &Path {
        match self {
            IssuerStore::Scratch(d) | IssuerStore::ProductFile(d) | IssuerStore::Product(d) => d,
        }
    }
}

/// The world (module docs).
pub struct World {
    /// The pairs and their servers (declared first: dropped, so stopped, before the
    /// scratch directory below is removed).
    pub pairs: Vec<Pair>,
    /// The scratch home: its root holds everything; `git_home` is the account home the
    /// projection writes (`HEIMDALL_TEST_SSH_HOME`), so `user_config` **is** P's file.
    pub home: ScratchHome,
    /// `HEIMDALL_HOME`.
    pub hh: PathBuf,
    /// The fake session-lock state file.
    pub lock_file: PathBuf,
    pub store: IssuerStore,
    pub ca_fingerprint: CaFingerprint,
    /// `ssh-ed25519 AAAA…` (no comment).
    pub ca_public: String,
    pub environment: EnvironmentId,
    pub identity: String,
    extra_env: Vec<(String, String)>,
    per_pair_profiles: bool,
    platform_session_lock: bool,
    product: bool,
    pair_policy_windows: Vec<Duration>,
    /// ⟨W6-R01⟩ Whether this world owns its projection's rollback.
    own_projection_rollback: bool,
    fail_after_apply: bool,
    fail_rollback: bool,
    /// ⟨W6-R01⟩ The projection's state.
    pub projection: Projection,
    pub transcript: Mutex<Transcript>,
    pub started: Timestamp,
    next: Mutex<u32>,
}

impl World {
    /// Build the world (module docs) and return it with the CA key, which the caller
    /// keeps only to derive what A33 scans for (it is never printed or written).
    pub fn start(mut o: WorldOptions) -> (World, SecretCaKey) {
        assert!(o.pairs >= 1, "a world has at least one pair");
        let started = Timestamp::now();
        let home = ScratchHome::new();
        let hh = home.root.join("hh");
        let lock_file = home.root.join("lock-state");
        std::fs::write(&lock_file, "unlocked").unwrap();
        if let Some(text) = &o.config_toml {
            for d in [hh.clone(), hh.join("config")] {
                std::fs::create_dir_all(&d).unwrap();
                owner_only(&d);
            }
            std::fs::write(hh.join("config").join("config.toml"), text).unwrap();
        }
        let store = if o.product {
            // The environment's directory is known after the first start (`set_up`).
            IssuerStore::Product(hh.join("state").join("issuer"))
        } else if cfg!(windows) {
            IssuerStore::ProductFile(hh.join("issuer-dpapi"))
        } else {
            IssuerStore::Scratch(hh.join("state").join("scratch-secret-store"))
        };
        let ca = SecretCaKey::generate().unwrap();
        let ca_fingerprint = ca.fingerprint().unwrap();
        let ca_public = ca.public_openssh().unwrap();

        // The servers, each trusting the CA for its own pair's principal only.
        let servers = if o.servers.is_empty() {
            (0..o.pairs)
                .map(|_| {
                    LoopbackSshd::start(
                        home.scratch(),
                        SshdConfig {
                            registry_seed: Some(Vec::new()),
                            ..SshdConfig::default()
                        },
                    )
                    .unwrap_or_else(|e| panic!("{e}"))
                })
                .collect::<Vec<_>>()
        } else {
            assert_eq!(o.servers.len(), o.pairs, "one server per pair");
            std::mem::take(&mut o.servers)
        };
        let mut pairs = Vec::new();
        for (i, sshd) in servers.into_iter().enumerate() {
            let account = sshd
                .login_account()
                .expect("the server's account is known (HM_FIXTURE_SSHD_USER on Windows)");
            let pair = Pair {
                alias: format!("exit{}", i + 1),
                destination: format!("ex{}", i + 1),
                account,
                sshd,
            };
            pair.sshd
                .append_registry_line(&format!(
                    "cert-authority,principals=\"{}\" {ca_public}",
                    pair.principal()
                ))
                .expect("the server has an account-form registry");
            home.trust_host_key(&pair.sshd.host_key_line).unwrap();
            pairs.push(pair);
        }
        let mut extra_env = o.extra_env;
        if let Some(seed) = &o.key_seed {
            extra_env.push((
                "HEIMDALL_TEST_KEY_SEED".to_owned(),
                seed.iter().map(|b| format!("{b:02x}")).collect(),
            ));
        }
        let mut w = World {
            home,
            hh,
            lock_file,
            store,
            pairs,
            ca_fingerprint,
            ca_public,
            // Replaced by the store's own environment in `set_up`.
            environment: EnvironmentId::from_random_bytes([0; 16]),
            identity: String::new(),
            extra_env,
            per_pair_profiles: o.per_pair_profiles,
            platform_session_lock: o.platform_session_lock,
            product: o.product,
            pair_policy_windows: o.pair_policy_windows,
            own_projection_rollback: o.product || o.own_projection_rollback,
            fail_after_apply: o.fail_after_apply,
            fail_rollback: o.fail_rollback,
            projection: Projection::NotApplied,
            transcript: Mutex::new(Transcript::default()),
            started,
            next: Mutex::new(0),
        };
        w.set_up(&ca);
        (w, ca)
    }

    fn set_up(&mut self, ca: &SecretCaKey) {
        // The catalog (the first command starts the runtime and creates the store).
        let key = heimdall_testkit::agent::FixtureKey::generate_many(1);
        let public = self.home.root.join("existing.pub");
        std::fs::write(
            &public,
            format!("{}\n", key[0].public_line_without_comment()),
        )
        .unwrap();
        let adopted = self.cli(&[
            "--json",
            "identity",
            "adopt",
            "--pub",
            &public.to_string_lossy(),
        ]);
        // ⟨M04, the Windows readiness failures⟩ The world's first command starts the runtime:
        // a refusal names the runtime's start-up timings.
        assert_eq!(
            adopted.code,
            0,
            "{adopted:?}\nruntime start-up: {}",
            runtime_start_log(&self.hh)
        );
        self.identity = adopted.json()["data"]["identity_id"]
            .as_str()
            .unwrap()
            .to_owned();
        for p in &self.pairs {
            let port = p.sshd.port.to_string();
            let add = self.cli(&[
                "--json",
                "destination",
                "add",
                &p.alias,
                "--hostname",
                &p.sshd.host,
                "--port",
                &port,
                "--account",
                &p.account,
                "--identity",
                &self.identity,
                "--id",
                &p.destination,
            ]);
            assert_eq!(add.code, 0, "{add:?}");
        }
        self.stop_runtime();

        // The seeded prerequisites, with the runtime stopped.
        let store = self.store.clone();
        let item = match &store {
            IssuerStore::Scratch(dir) => {
                std::fs::create_dir_all(dir).unwrap();
                owner_only(dir);
                heimdall_testkit::scratch_store::ScratchSecretStore::new(dir.clone())
                    .put(&self.ca_fingerprint, ca)
                    .unwrap()
            }
            IssuerStore::ProductFile(dir) => {
                product_file_put(dir, &self.db(), &self.ca_fingerprint, ca)
            }
            IssuerStore::Product(base) => {
                let (dir, item) = product_put(base, &self.db(), &self.ca_fingerprint, ca);
                self.store = IssuerStore::Product(dir);
                item
            }
        };
        let store_kind = if cfg!(windows) {
            StoreKind::WindowsDpapi
        } else {
            StoreKind::LinuxSecretService
        };
        let now = Timestamp::now();
        let client = client_version_line();
        let identity = IdentityId::parse(&self.identity).unwrap();
        // The existing access's agent endpoint a real record carries (no agent runs here:
        // only a verification's plan is rebuilt from it, and the verification never
        // uses it).
        let existing = if cfg!(windows) {
            "//./pipe/hm-exit-existing-agent".to_owned()
        } else {
            self.home
                .root
                .join("existing-agent.sock")
                .to_string_lossy()
                .into_owned()
        };
        let records: Vec<EnrollmentRecord> = self
            .pairs
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let ca = (&self.ca_fingerprint, self.ca_public.as_str());
                enrollment(i, p, ca, &identity, &existing, &client, now)
            })
            .collect();
        let pairs: std::collections::BTreeSet<AccessPair> = self
            .pairs
            .iter()
            .map(|p| AccessPair {
                destination: DestinationId::parse(&p.destination).unwrap(),
                account: AccountName::parse(&p.account).unwrap(),
            })
            .collect();
        let mut profiles = vec![(
            PROFILE.to_owned(),
            POLICY.to_owned(),
            pairs.clone(),
            DEFAULT_POLICY_WINDOW,
        )];
        if self.per_pair_profiles {
            for (i, p) in self.pairs.iter().enumerate() {
                let pair = AccessPair {
                    destination: DestinationId::parse(&p.destination).unwrap(),
                    account: AccountName::parse(&p.account).unwrap(),
                };
                profiles.push((
                    self.profile_of(i),
                    format!("{POLICY}-{}", i + 1),
                    [pair].into_iter().collect(),
                    self.pair_policy_windows
                        .get(i)
                        .copied()
                        .unwrap_or(DEFAULT_POLICY_WINDOW),
                ));
            }
        }
        let (fp, public) = (self.ca_fingerprint.clone(), self.ca_public.clone());
        let environment = self
            .open_store()
            .transaction(|tx| {
                tx.insert_issuer(&IssuerRecord {
                    ca_fingerprint: fp.clone(),
                    public_key: public.clone(),
                    state: CaState::Active,
                    store_kind,
                    backup_sha256: "ab".repeat(32),
                    backup_created_at: now,
                    restored_without_log: false,
                    created_at: now,
                    retired_at: None,
                })?;
                tx.set_issuer_store_locator(&fp, &item.locator)?;
                for r in &records {
                    tx.seed_enrollment(r)?;
                }
                let env = tx
                    .self_environment()?
                    .expect("the runtime recorded its environment");
                let ssh: std::collections::BTreeSet<Capability> =
                    [Capability::SshAuthentication].into_iter().collect();
                for (profile, policy, pairs, window) in &profiles {
                    let scope = Scope {
                        pairs: pairs.clone(),
                        capabilities: ssh.clone(),
                    };
                    let profile = ProfileId::parse(profile).unwrap();
                    tx.upsert_profile(&ProfileDefinition {
                        id: profile.clone(),
                        revision: 1,
                        scope: scope.clone(),
                        label: None,
                    })?;
                    tx.upsert_policy(
                        &StandingPolicy {
                            id: PolicyId::parse(policy).unwrap(),
                            revision: PolicyRevision(1),
                            profile,
                            workspace: None,
                            scope,
                            environments: [env.clone()].into_iter().collect(),
                            max_window: *window,
                            pause: PauseState::Active,
                            cutoff_at: None,
                            source: PolicySource::SetupDefault,
                            lock_behavior: heimdall_contract::managed::LockBehavior::Continue,
                            connection: heimdall_contract::managed::ConnectionPolicy::default(),
                        },
                        false,
                    )?;
                }
                Ok(env)
            })
            .unwrap();
        self.environment = environment;

        // The preference (starts the runtime, whose issuer child loads the CA), then the
        // issuing CA (E5 records it after the preference).
        for p in &self.pairs {
            let prefer = self.cli(&["--json", "destination", "prefer", &p.alias, "managed"]);
            assert_eq!(prefer.code, 0, "{prefer:?}");
        }
        let status = self.cli(&["--json", "issuer", "status"]);
        assert_eq!(status.json()["data"]["state"], "ready", "{status:?}");
        let fp = self.ca_fingerprint.clone();
        let ps: Vec<AccessPair> = pairs.into_iter().collect();
        self.open_store()
            .transaction(|tx| {
                for pair in &ps {
                    tx.add_issuing_ca(pair, &fp, now)?;
                }
                Ok(())
            })
            .unwrap();
        // P names the aliases, and this boot's time is confirmed (the issuer child's
        // read-only gate needs a same-boot reference): both typed on a terminal.
        // ⟨W6-R01⟩ From here a rollback is owed: a failure after this point unwinds through
        // `Drop`, which rolls the projection back (or keeps the recovery state).
        if self.own_projection_rollback {
            self.projection = Projection::MayBeApplied;
        }
        let applied = self.confirm(&["setup", "apply"]);
        assert!(
            !self.fail_after_apply,
            "injected failure after setup apply (W6-R01 regression)"
        );
        assert_eq!(
            applied.code,
            0,
            "setup apply: {}",
            self.redact(&applied.stdout)
        );
        if self.product {
            // The product projection is the account's own configuration (the caller
            // guarded that it is a disposable account's): the scratch user
            // configuration every client gets with `-F` is a byte copy of it.
            let account = heimdall_localenv::sys::account_home()
                .expect("the account home (the product projection's)");
            let text = std::fs::read(account.join(".ssh").join("config"))
                .expect("setup apply wrote the account's SSH configuration");
            std::fs::write(&self.home.user_config, text).unwrap();
        }
        let confirmed = self.confirm(&["time", "confirm"]);
        assert_eq!(
            confirmed.code,
            0,
            "time confirm: {}",
            self.redact(&confirmed.stdout)
        );
        // The default-identity guard over P for every alias: each one's identity list
        // is certainly the projection's scratch files, never the account's defaults.
        // ⟨M03 wave 6⟩ On Windows the projection's agent is this world's own runtime's pipe
        // (`\\.\pipe\heimdall-…`, which no scratch path can hold): the guard also accepts
        // exactly the pipes this runtime rendered into its managed file under the scratch
        // Heimdall home, and nothing else (never the system agent's pipe).
        let own_agents = self.rendered_agents();
        for p in &self.pairs {
            self.home
                .check_alias_with_agents(&p.alias, &own_agents)
                .unwrap_or_else(|e| panic!("the projection of {}: {e:?}", p.alias));
        }
    }

    // ---- processes ---------------------------------------------------------------------

    /// The environment of every process the world starts (module docs).
    pub fn env(&self) -> Vec<(OsString, OsString)> {
        let mut e: Vec<(OsString, OsString)> = Vec::new();
        let mut put = |k: &str, v: &OsStr| e.push((k.into(), v.to_owned()));
        put("HEIMDALL_HOME", self.hh.as_os_str());
        put("HOME", self.home.git_home.as_os_str());
        put("GIT_CONFIG_NOSYSTEM", OsStr::new("1"));
        // The product configuration ([`WorldOptions::product`]) sets no test variable.
        if !self.product {
            put("HEIMDALL_TEST_ADAPTER", OsStr::new("prepare"));
            put("HEIMDALL_TEST_TIME_SYNC", OsStr::new("synchronized"));
            if !self.platform_session_lock {
                put("HEIMDALL_TEST_SESSION_LOCK", self.lock_file.as_os_str());
            }
            put("HEIMDALL_TEST_SSH_HOME", self.home.git_home.as_os_str());
            let store = match &self.store {
                IssuerStore::Scratch(_) => OsString::from("scratch"),
                IssuerStore::ProductFile(dir) | IssuerStore::Product(dir) => {
                    let mut s = OsString::from(heimdall_product_file_prefix());
                    s.push(dir.as_os_str());
                    s
                }
            };
            put("HEIMDALL_TEST_SECRET_STORE", &store);
        }
        if cfg!(windows) {
            for k in ["SystemRoot", "PATH", "TEMP", "TMP"] {
                if let Some(v) = std::env::var_os(k) {
                    put(k, &v);
                }
            }
        } else {
            put("PATH", OsStr::new("/usr/bin:/bin"));
        }
        // The runtime's verification `ssh` inherits this environment.
        #[cfg(windows)]
        for (k, v) in openssh_startup_env() {
            put(k, &v);
        }
        for (k, v) in &self.extra_env {
            put(k, OsStr::new(v));
        }
        e
    }

    /// Run the binary (cleared environment, stdin closed, the scratch root as working
    /// directory); the output joins the transcript.
    pub fn cli(&self, args: &[&str]) -> Out {
        let out = Command::new(bin())
            .args(args)
            .env_clear()
            .envs(self.env())
            .current_dir(&self.home.root)
            .stdin(Stdio::null())
            .output()
            .expect("spawn heimdall");
        let out = Out {
            code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        };
        self.record(args, &out.stdout, &out.stderr);
        assert!(!out.stderr.contains("panicked"), "{args:?}: {out:?}");
        out
    }

    /// Run the binary on a terminal and type `yes` at its `[y/N]: ` prompt.
    pub fn confirm(&self, args: &[&str]) -> Out {
        let mut cmd = TerminalCommand::new(bin())
            .args(args)
            .current_dir(&self.home.root);
        for (k, v) in self.env() {
            cmd = cmd.env(k, v);
        }
        let mut term = cmd.spawn().unwrap_or_else(|e| {
            panic!("blocked: a terminal (script(1) on Unix, ConPTY on Windows) is needed: {e}")
        });
        if let Err(e) = term.expect("[y/N]: ", Duration::from_secs(90)) {
            panic!("{args:?}: no prompt: {}", self.redact(&e.to_string()));
        }
        term.send(b"yes\r").unwrap();
        let code = term.wait(Duration::from_secs(120)).unwrap_or(-1);
        let text = term.text();
        self.record(args, &text, "");
        Out {
            code,
            stdout: text,
            stderr: String::new(),
        }
    }

    fn record(&self, args: &[&str], stdout: &str, stderr: &str) {
        let label = args
            .iter()
            .filter(|a| !a.starts_with('-') && !a.contains(['/', '\\']))
            .take(3)
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        let mut t = self.transcript.lock().unwrap();
        t.entries
            .push((format!("{label} (stdout)"), stdout.as_bytes().to_vec()));
        t.entries
            .push((format!("{label} (stderr)"), stderr.as_bytes().to_vec()));
    }

    /// Record bytes another part of the suite captured (a worker's streams).
    pub fn record_bytes(&self, label: &str, bytes: &[u8]) {
        self.transcript
            .lock()
            .unwrap()
            .entries
            .push((label.to_owned(), bytes.to_vec()));
    }

    /// `text` with the scratch root and the accounts replaced (a failure message).
    pub fn redact(&self, text: &str) -> String {
        let mut s = text.replace(&*self.home.root.to_string_lossy(), "<scratch>");
        for p in &self.pairs {
            if !p.account.is_empty() {
                s = s.replace(&p.account, "<user>");
            }
        }
        s
    }

    /// `service stop` of this world's runtime (a no-op when none runs).
    pub fn stop_runtime(&self) {
        let out = self.cli(&["--json", "service", "stop"]);
        assert!(matches!(out.code, 0 | 5), "{out:?}");
    }

    /// **The re-issue trigger the product supports** (ADR-0008 D6 item 4; m03-plan U10
    /// `reissue_after_runtime_process_restart_same_boot`): the runtime process is
    /// stopped and started again in the same boot. Its K_env lived only in the old
    /// process, so the grant's instance is `lost`; the new process starts its issuer
    /// child, then its re-issue pass re-issues the continuing grant through that child.
    /// [`World::start_runtime`] starts it again.
    pub fn restart_runtime(&self) {
        let before = self.runtime_pid();
        self.stop_runtime();
        self.start_runtime();
        let status = self.cli(&["--json", "issuer", "status"]);
        assert_eq!(status.json()["data"]["state"], "ready", "{status:?}");
        assert_ne!(before, self.runtime_pid(), "a new runtime process");
    }

    /// Start the runtime on demand with an effectful command that changes nothing:
    /// `access release` of a binding that does not exist (`NOT_FOUND`). Read-only
    /// commands never start it.
    pub fn start_runtime(&self) {
        let out = self.cli(&[
            "--json",
            "access",
            "release",
            "binding_00000000000000000000000000000000",
        ]);
        assert_eq!(out.json()["code"], "NOT_FOUND", "{out:?}");
        let status = self.cli(&["--json", "service", "status"]);
        assert_eq!(status.code, 0, "the runtime serves: {status:?}");
    }

    /// The state database.
    pub fn db(&self) -> PathBuf {
        self.hh.join("state").join("state.db")
    }

    /// The store, opened by this test (a second writer beside the runtime, as the
    /// seeding of `cli_m03`'s managed pair does).
    pub fn open_store(&self) -> Store {
        Store::open(&self.db(), Arc::new(NoFaults)).unwrap()
    }

    /// The runtime's advertisement (`<run>/instance.json`: its PID and its control and
    /// signing endpoints; no secrets).
    pub fn instance(&self) -> Value {
        let text = std::fs::read(self.hh.join("run").join("instance.json"))
            .expect("the runtime advertises itself");
        serde_json::from_slice(&text).unwrap()
    }

    /// The PID of the runtime now serving (its advertisement), checked alive.
    pub fn runtime_pid(&self) -> u32 {
        let pid = u32::try_from(self.instance()["pid"].as_u64().unwrap()).unwrap();
        assert!(crate::procs::alive(pid), "the advertised runtime is alive");
        pid
    }

    /// The profile of pair `i` alone (`exit-<i + 1>`; [`WorldOptions::per_pair_profiles`]).
    pub fn profile_of(&self, i: usize) -> String {
        format!("{PROFILE}-{}", i + 1)
    }

    /// `access ensure --profile exit` for `work` (exit 0 asserted); the result's data.
    pub fn ensure(&self, work: &str, request: &str) -> Value {
        self.ensure_on(PROFILE, work, request)
    }

    /// [`World::ensure`] of `profile`.
    pub fn ensure_on(&self, profile: &str, work: &str, request: &str) -> Value {
        let out = self.cli(&[
            "--json",
            "access",
            "ensure",
            "--profile",
            profile,
            "--work-id",
            work,
            "--request-id",
            request,
        ]);
        assert_eq!(out.code, 0, "ensure: {}", self.redact(&format!("{out:?}")));
        let env = out.json();
        assert_eq!(
            env["code"],
            "ACCESS_READY",
            "{}",
            self.redact(&format!("{out:?}"))
        );
        assert_eq!(
            env["data"]["credential_mechanism"], "managed_certificate",
            "{env}"
        );
        env["data"].clone()
    }

    /// `access revoke <grant>` (exit 0 and `local_applied` asserted).
    pub fn revoke(&self, grant: &str, request: &str) -> Value {
        let out = self.cli(&["--json", "access", "revoke", grant, "--request-id", request]);
        assert_eq!(out.code, 0, "revoke: {}", self.redact(&format!("{out:?}")));
        let env = out.json();
        assert_eq!(env["data"]["local_applied"], true, "{env}");
        env["data"].clone()
    }

    /// The stored grant `id`'s state (`active`, `ended`, …).
    pub fn grant_state(&self, id: &str) -> String {
        let gid = heimdall_contract::ids::GrantId::parse(id).unwrap();
        self.open_store()
            .transaction(|tx| tx.grant(&gid))
            .unwrap()
            .map(|g| {
                serde_json::to_value(g.state)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }

    /// The published issuance entries of grant `id` signed under the world's CA:
    /// `(serial, key ID)`, in log order.
    pub fn published(&self, id: &str) -> Vec<(u64, String)> {
        let gid = heimdall_contract::ids::GrantId::parse(id).unwrap();
        let ca = self.ca_fingerprint.clone();
        self.open_store()
            .transaction(|tx| tx.issuance_entries(&gid))
            .unwrap()
            .into_iter()
            .filter(|e| {
                e.state == heimdall_domain::issuance::IssuanceState::Published
                    && e.bounds.ca_fingerprint.as_ref() == Some(&ca)
            })
            .map(|e| (e.bounds.serial, e.bounds.key_id))
            .collect()
    }

    /// Wait (bounded) until every grant of `grants` is `active` with `published`
    /// certificates signed under the world's CA (the re-issue pass runs at start and is
    /// retried by the supervisor).
    pub fn wait_reissued(&self, grants: &[&str], published: usize) {
        let start = Instant::now();
        loop {
            let done = grants
                .iter()
                .all(|g| self.grant_state(g) == "active" && self.published(g).len() == published);
            if done {
                return;
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "not re-issued in time: {:?}",
                grants
                    .iter()
                    .map(|g| (self.grant_state(g), self.published(g).len()))
                    .collect::<Vec<_>>()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// A fresh scratch directory for one worker or probe.
    pub fn subdir(&self, prefix: &str) -> PathBuf {
        let n = {
            let mut g = self.next.lock().unwrap();
            *g += 1;
            *g
        };
        let d = self.home.root.join(format!("{prefix}{n}"));
        std::fs::create_dir(&d).unwrap();
        owner_only(&d);
        d
    }

    // ---- logins -------------------------------------------------------------------------

    /// The client command a fresh login runs: the system `ssh` with only the isolation
    /// arguments, `<alias>`, `echo <marker>`; the environment the decoy agent, the
    /// scratch `HOME` and (Windows) what the in-box client needs. As `(program, args,
    /// env)` so a worker process can run it.
    pub fn login_command(
        &self,
        pair: usize,
        marker: &str,
    ) -> (PathBuf, Vec<OsString>, Vec<(OsString, OsString)>) {
        let p = &self.pairs[pair];
        let mut args = self.home.isolation_args();
        args.push(p.alias.clone().into());
        args.push(format!("echo {marker}").into());
        let mut env: Vec<(OsString, OsString)> = vec![
            (
                "SSH_AUTH_SOCK".into(),
                self.home.decoy_agent().endpoint().locator(),
            ),
            ("HOME".into(), self.home.git_home.clone().into_os_string()),
        ];
        if cfg!(windows) {
            for k in [
                "SystemRoot",
                "PATH",
                "TEMP",
                "TMP",
                "USERNAME",
                "USERPROFILE",
            ] {
                if let Some(v) = std::env::var_os(k) {
                    env.push((k.into(), v));
                }
            }
        } else {
            env.push(("PATH".into(), "/usr/bin:/bin".into()));
        }
        #[cfg(windows)]
        for (k, v) in openssh_startup_env() {
            env.push((k.into(), v));
        }
        (openssh("ssh"), args, env)
    }

    /// A fresh login from this test process (no `run`, so no binding holds the pair's
    /// slot): the projection alone.
    pub fn projection_login(&self, pair: usize, marker: &str) -> Out {
        let (program, args, env) = self.login_command(pair, marker);
        let out = run_bounded(
            Command::new(program)
                .args(args)
                .env_clear()
                .envs(env)
                .current_dir(&self.home.root),
            Duration::from_secs(60),
        );
        self.record_bytes("projection login (stdout)", out.stdout.as_bytes());
        self.record_bytes("projection login (stderr)", out.stderr.as_bytes());
        out
    }

    /// The certificates `pair`'s server accepted after `mark` (its log position).
    pub fn accepted_since(
        &self,
        pair: usize,
        mark: u64,
    ) -> Vec<heimdall_testkit::sshd::AcceptedCert> {
        let sshd = &self.pairs[pair].sshd;
        sshd.log_lines_since(mark, "Accepted publickey for ")
            .iter()
            .filter_map(|l| parse_accepted_cert(l))
            .collect()
    }

    // ---- workers --------------------------------------------------------------------------

    /// Start a worker on the profile's managed binding: `heimdall run --profile exit
    /// --work-id <work> --request-id <request> -- <this test binary> --exact
    /// worker_process_entry …`, the worker reading `tasks` ([`crate::worker`]). Its
    /// stdout and stderr are pipes this test made, whose identities it reports
    /// ([`Worker::stdout_identity`], [`Worker::stderr_identity`]).
    pub fn spawn_worker(&self, work: &str, request: &str, tasks: Vec<Value>) -> Worker {
        self.spawn_worker_on(PROFILE, work, request, tasks)
    }

    /// [`World::spawn_worker`] on `profile`'s binding.
    pub fn spawn_worker_on(
        &self,
        profile: &str,
        work: &str,
        request: &str,
        tasks: Vec<Value>,
    ) -> Worker {
        let dir = self.subdir("worker");
        let instructions = dir.join("instructions.json");
        let result = dir.join("result.json");
        std::fs::write(
            &instructions,
            serde_json::to_vec(&serde_json::json!({
                "result": result,
                "tasks": tasks,
            }))
            .unwrap(),
        )
        .unwrap();
        let exe = std::env::current_exe().unwrap();
        let (reader, writer) = std::io::pipe().unwrap();
        let (writer, stdout_identity) = pipe_identity(writer);
        let (err_reader, err_writer) = std::io::pipe().unwrap();
        let (err_writer, stderr_identity) = pipe_identity(err_writer);
        let mut cmd = Command::new(bin());
        cmd.args([
            "run",
            "--profile",
            profile,
            "--work-id",
            work,
            "--request-id",
            request,
            "--",
        ])
        .arg(&exe)
        .args([
            "--exact",
            "worker_process_entry",
            "--nocapture",
            "--test-threads=1",
            "-q",
        ])
        .env_clear()
        .envs(self.env())
        .env(WORKER_ENV, &instructions)
        .current_dir(&self.home.root)
        .stdin(Stdio::null())
        .stdout(writer)
        .stderr(err_writer);
        let child = cmd.spawn().expect("spawn heimdall run");
        // This process's copies of the write ends go with the command, so the readers
        // see the streams end when the worker ends.
        drop(cmd);
        Worker {
            child: Some(child),
            stdout: Some(drain(reader)),
            stderr: Some(drain(err_reader)),
            result,
            dir,
            stdout_identity,
            stderr_identity,
        }
    }
}

impl World {
    /// The configuration file the projection writes: the account's own `.ssh/config`
    /// in the product configuration, else the scratch SSH home's
    /// (`HEIMDALL_TEST_SSH_HOME`).
    fn projection_config(&self) -> Option<PathBuf> {
        if self.product {
            heimdall_localenv::sys::account_home()
                .ok()
                .map(|h| h.join(".ssh").join("config"))
        } else {
            Some(self.home.git_home.join(".ssh").join("config"))
        }
    }

    /// The `IdentityAgent` values this world's runtime rendered into its managed SSH
    /// configuration (`<hh>/config/ssh_config`, under the scratch Heimdall home).
    fn rendered_agents(&self) -> Vec<String> {
        std::fs::read_to_string(self.hh.join("config").join("ssh_config"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| {
                let l = l.trim();
                let (key, value) = l.split_once(char::is_whitespace)?;
                key.eq_ignore_ascii_case("identityagent")
                    .then(|| value.trim().trim_matches('"').to_owned())
            })
            .collect()
    }

    /// ⟨W6-R01⟩ Whether the projection is restored: the projected configuration is
    /// absent, or holds nothing of Heimdall's (before the apply it was absent or empty:
    /// the product configuration's guard, a fresh scratch home otherwise).
    fn projection_restored(&self) -> Result<(), String> {
        let Some(path) = self.projection_config() else {
            return Err("the projected configuration's location is unknown".to_owned());
        };
        match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!(
                "the projected configuration is unreadable: {}",
                e.kind()
            )),
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).to_ascii_lowercase();
                let hh = self
                    .hh
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .replace('\\', "/");
                if text.contains("heimdall") || text.replace('\\', "/").contains(&hh) {
                    Err("the projected configuration still names Heimdall's projection".to_owned())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// ⟨W6-R01⟩ Roll the projection back if a rollback is owed: `setup rollback` must
    /// exit 0 and the restoration must verify. A nonzero exit, a timeout, a
    /// panic or a failed verification keeps the scratch home (the projection's state
    /// and backups) for recovery and returns the failure; nothing is deleted then.
    pub fn rollback_projection(&mut self) -> Result<String, String> {
        if self.projection != Projection::MayBeApplied {
            return Ok(format!(
                "projection rollback: none owed ({:?})",
                self.projection
            ));
        }
        let attempt: Result<(), String> = if self.fail_rollback {
            Err("injected rollback failure (W6-R01 regression)".to_owned())
        } else {
            // `setup rollback` restores without a typed confirmation (it only returns to
            // a state the owner consented to), so it runs as an ordinary command.
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.cli(&["--json", "--non-interactive", "setup", "rollback"])
            })) {
                Ok(o) if o.code == 0 => self.projection_restored(),
                Ok(o) => Err(format!("setup rollback exited {}", o.code)),
                Err(_) => Err("setup rollback panicked or timed out".to_owned()),
            }
        };
        match attempt {
            Ok(()) => {
                self.projection = Projection::RolledBack;
                Ok("projection rollback: setup rollback exit 0, restoration verified".to_owned())
            }
            Err(why) => {
                self.home.keep_on_drop();
                let text = format!(
                    "projection rollback FAILED ({why}): the scratch home holding the projection's state and backups is kept for recovery"
                );
                self.projection = Projection::Kept(text.clone());
                Err(text)
            }
        }
    }
}

impl Drop for World {
    fn drop(&mut self) {
        // ⟨W6-R01⟩ A rollback still owed (a preparation that failed after `setup apply`,
        // or a caller that never ran its cleanup) runs first, while the runtime's home is
        // intact; its result is reported to the caller and on stderr.
        if self.projection == Projection::MayBeApplied {
            let r = self.rollback_projection();
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "m03 observation: lock cleanup {}",
                    r.as_ref().map_or_else(|e| e, |t| t)
                );
            }
            PROJECTION_CLEANUPS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(ProjectionCleanup {
                    result: r,
                    root: self.home.root.clone(),
                });
        }
        // The runtime this world started, in its own home (a no-op when none runs), and
        // ⟨M04, the Windows readiness failures⟩ any it started that had not advertised yet
        // (a CLI that gave up waiting leaves its runtime starting): the servers and the
        // scratch directory go with their own handles after this.
        let killed = stop_started_runtimes(&self.env(), &self.hh.join("state"), &self.home.root);
        if killed > 0 {
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "runtime guard: {killed} runtime(s) of this world did not stop through `service stop` and were killed by exact identity"
                );
            }
        }
    }
}

/// ⟨M04, the Windows readiness failures; as M05's A29 fixture⟩ Stop every runtime the test
/// configuration started in the installation whose state directory is `state` (`env`: its
/// CLI environment; `cwd`: where the CLI runs), a runtime that has not advertised yet
/// included. Each runtime appends `<pid> <start token>` to `<state>/test-service-starts`
/// before it takes the instance lock (`testcfg::record_start`).
///
/// 1. `service stop` (graceful; a no-op until a runtime advertises), again every 500 ms,
///    for up to 30 s while a recorded runtime is still alive (the same PID and start token).
/// 2. Each recorded runtime still alive then is pinned (`ProcessPin`: a pidfd on Linux, a
///    process handle on Windows), its start token compared again after the pin and its image
///    checked to be this suite's `heimdall`, and only then killed. On Linux a runtime is
///    non-dumpable, so its image cannot be read: it is checked by the command name in
///    `/proc/<pid>/stat` and killed through a pidfd of its own, the token compared again
///    after that pidfd. Then up to 10 s for it to be gone.
///
/// Returns how many were killed (0 when every one stopped gracefully).
pub fn stop_started_runtimes(env: &[(OsString, OsString)], state: &Path, cwd: &Path) -> usize {
    stop_started_runtimes_within(env, state, cwd, Duration::from_secs(30))
}

/// [`stop_started_runtimes`] with `grace` for step 1 (the guard's own test shortens it).
pub fn stop_started_runtimes_within(
    env: &[(OsString, OsString)],
    state: &Path,
    cwd: &Path,
    grace: Duration,
) -> usize {
    use heimdall_localenv::sys::{ProcessPin, ProcessSignal};
    let records: Vec<(u32, String)> = std::fs::read_to_string(state.join("test-service-starts"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            let pid = words.next()?.parse().ok()?;
            Some((pid, words.next()?.to_owned()))
        })
        .collect();
    let alive = || -> Vec<(u32, String)> {
        records
            .iter()
            .filter(|(pid, token)| {
                heimdall_runtime::platform::process_start_time(*pid).as_deref()
                    == Some(token.as_str())
            })
            .cloned()
            .collect()
    };
    let stop = || {
        let _ = Command::new(bin())
            .args(["--json", "service", "stop"])
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k, v)))
            .current_dir(cwd)
            .stdin(Stdio::null())
            .output();
    };
    stop();
    let deadline = Instant::now() + grace;
    while !alive().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
        stop();
    }
    let mut killed = Vec::new();
    for (pid, token) in alive() {
        let pin = match ProcessPin::open(pid) {
            Ok(Some(pin)) => pin,
            Ok(None) => {
                guard_note("gone before it was pinned");
                continue;
            }
            Err(e) => {
                guard_note(&format!("not pinned ({e})"));
                continue;
            }
        };
        let same =
            heimdall_runtime::platform::process_start_time(pid).as_deref() == Some(token.as_str());
        if !same {
            guard_note("its start token changed (another process): left alone");
            continue;
        }
        let expected = Path::new(&bin()).to_path_buf();
        match pin.image() {
            // ⟨Linux⟩ The runtime makes itself non-dumpable (`harden_process`), which hides
            // `/proc/<pid>/exe` from its own user: identified instead through a pidfd of its
            // own, the start token read again after it, and the command name.
            #[cfg(target_os = "linux")]
            None => {
                if kill_hardened_runtime(pid, &token, &expected) {
                    killed.push((pid, token));
                }
                continue;
            }
            #[cfg(not(target_os = "linux"))]
            None => {
                guard_note("its image could not be read: left alone");
                continue;
            }
            Some(image) if !image_is(&image, &expected) => {
                guard_note(&format!(
                    "its image is not this suite's heimdall (named {:?}, expected {:?}): left alone",
                    image.file_name().unwrap_or_default(),
                    expected.file_name().unwrap_or_default()
                ));
                continue;
            }
            Some(_) => {}
        }
        match pin.verify(true, &expected) {
            Some(verified) => match verified.signal(ProcessSignal::Kill) {
                Ok(()) => killed.push((pid, token)),
                Err(e) => guard_note(&format!("not killed ({e})")),
            },
            None => guard_note("not verified: left alone"),
        }
    }
    let gone_by = Instant::now() + Duration::from_secs(10);
    while Instant::now() < gone_by
        && killed.iter().any(|(pid, token)| {
            heimdall_runtime::platform::process_start_time(*pid).as_deref() == Some(token.as_str())
        })
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    killed.len()
}

/// ⟨Linux⟩ Kill the recorded runtime `pid` whose image cannot be read (it is non-dumpable):
/// only through a pidfd opened here, once the start token read after that pidfd is still
/// `token` (the same process instance) and the command name in `/proc/<pid>/stat` is
/// `expected`'s file name (as the kernel keeps it, at most 15 bytes).
#[cfg(target_os = "linux")]
fn kill_hardened_runtime(pid: u32, token: &str, expected: &Path) -> bool {
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
    let Some(raw) = i32::try_from(pid).ok().and_then(Pid::from_raw) else {
        return false;
    };
    let Ok(fd) = pidfd_open(raw, PidfdFlags::empty()) else {
        guard_note("could not be pinned: left alone");
        return false;
    };
    if heimdall_runtime::platform::process_start_time(pid).as_deref() != Some(token) {
        guard_note("its start token changed (another process): left alone");
        return false;
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let comm = match (stat.find('('), stat.rfind(')')) {
        (Some(a), Some(b)) if a < b => &stat[a + 1..b],
        _ => "",
    };
    let want: String = expected
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .chars()
        .take(15)
        .collect();
    if comm != want {
        guard_note("its command name is not this suite's heimdall: left alone");
        return false;
    }
    match pidfd_send_signal(&fd, Signal::KILL) {
        Ok(()) => true,
        Err(e) => {
            guard_note(&format!("not killed (os error {})", e.raw_os_error()));
            false
        }
    }
}

/// A runtime guard's note on stderr (no path above a file name, no identity).
fn guard_note(what: &str) {
    #[allow(clippy::print_stderr)]
    {
        eprintln!("runtime guard: a recorded runtime {what}");
    }
}

/// Whether `image` (as the OS reports a process's executable) is `expected`, as
/// `ProcessPin::verify` compares them (Unix: after canonicalizing `expected`; Windows:
/// case-insensitively).
fn image_is(image: &Path, expected: &Path) -> bool {
    #[cfg(windows)]
    {
        let strip = |p: &Path| {
            let s = p.to_string_lossy().into_owned();
            s.strip_prefix("\\\\?\\").map(str::to_owned).unwrap_or(s)
        };
        strip(image).eq_ignore_ascii_case(&strip(expected))
    }
    #[cfg(not(windows))]
    {
        let expected = std::fs::canonicalize(expected).unwrap_or_else(|_| expected.to_path_buf());
        image == expected
    }
}

/// ⟨M04, the Windows readiness failures⟩ The runtime log's start-up lines of the installation
/// whose `HEIMDALL_HOME` is `hh` ("the runtime starts", with the time before the runtime's own
/// start; "the runtime advertised its endpoints", with each phase's), for a failure message.
pub fn runtime_start_log(hh: &Path) -> String {
    let mut lines = Vec::new();
    for name in ["heimdall.log.1", "heimdall.log"] {
        if let Ok(text) = std::fs::read_to_string(hh.join("log").join(name)) {
            lines.extend(
                text.lines()
                    .filter(|l| {
                        l.contains("the runtime starts")
                            || l.contains("the runtime advertised its endpoints")
                    })
                    .map(str::to_owned),
            );
        }
    }
    if lines.is_empty() {
        "no start-up line in the runtime log".to_owned()
    } else {
        lines.join("\n")
    }
}

/// A worker running under `heimdall run` ([`World::spawn_worker`]).
pub struct Worker {
    child: Option<Child>,
    stdout: Option<JoinHandle<Vec<u8>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
    result: PathBuf,
    pub dir: PathBuf,
    /// The identity of the stdout pipe this test gave it (Linux: the pipe inode; macOS:
    /// the write end's address, as `fstat` and `lsof` show it).
    pub stdout_identity: u64,
    /// The same for its stderr pipe.
    pub stderr_identity: u64,
}

/// What a finished worker produced.
#[derive(Debug)]
pub struct WorkerOut {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub results: Vec<Value>,
}

impl Worker {
    /// The PID of the worker (Unix: `run` execs the worker in its own process).
    pub fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Wait until the worker created `signal` (a `signal` task), its results so far.
    pub fn wait_signal(&mut self, signal: &Path, timeout: Duration) -> Vec<Value> {
        let start = Instant::now();
        while !signal.exists() {
            if let Some(child) = self.child.as_mut()
                && let Ok(Some(status)) = child.try_wait()
            {
                let out = self.finish_inner(status.code().unwrap_or(-1));
                panic!("the worker ended before its signal: {out:?}");
            }
            assert!(
                start.elapsed() < timeout,
                "no signal from the worker in {timeout:?}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        self.results()
    }

    /// Its results so far.
    pub fn results(&self) -> Vec<Value> {
        std::fs::read(&self.result)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
    }

    /// Wait (bounded) for the worker to end; killed through its handle at the deadline.
    pub fn finish(mut self, timeout: Duration) -> WorkerOut {
        let start = Instant::now();
        let code = loop {
            let child = self.child.as_mut().unwrap();
            if let Ok(Some(status)) = child.try_wait() {
                break status.code().unwrap_or(-1);
            }
            if start.elapsed() > timeout {
                let _ = child.kill();
                let _ = child.wait();
                break -1;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        self.finish_inner(code)
    }

    fn finish_inner(&mut self, code: i32) -> WorkerOut {
        if let Some(mut c) = self.child.take() {
            let _ = c.wait();
        }
        let stdout = self
            .stdout
            .take()
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        let stderr = self
            .stderr
            .take()
            .map(|h| h.join().unwrap_or_default())
            .unwrap_or_default();
        WorkerOut {
            code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            results: self.results(),
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Never leave the worker running: it is ours, by its handle.
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// ---- helpers ----------------------------------------------------------------------------

/// Run `cmd` (stdin closed), killed through its handle after `timeout`.
pub fn run_bounded(cmd: &mut Command, timeout: Duration) -> Out {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let out = drain(child.stdout.take().unwrap());
    let err = drain(child.stderr.take().unwrap());
    let start = Instant::now();
    let code = loop {
        if let Ok(Some(s)) = child.try_wait() {
            break s.code().unwrap_or(-1);
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            break -1;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    Out {
        code,
        stdout: String::from_utf8_lossy(&out.join().unwrap_or_default()).into_owned(),
        stderr: String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned(),
    }
}

/// Read `r` to its end on a thread.
pub fn drain<R: std::io::Read + Send + 'static>(mut r: R) -> JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = r.read_to_end(&mut buf);
        buf
    })
}

/// The pipe write end as a child's stdio, and its identity (module docs of
/// [`crate::procs`]): Linux the pipe's inode, macOS the end's address (`fstat`'s
/// `st_ino`, which `lsof` shows as the device); 0 on Windows (not compared).
fn pipe_identity(writer: std::io::PipeWriter) -> (Stdio, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let fd = std::os::fd::OwnedFd::from(writer);
        let file = std::fs::File::from(fd);
        let ino = file.metadata().map(|m| m.ino()).unwrap_or(0);
        (Stdio::from(file), ino)
    }
    #[cfg(not(unix))]
    {
        (Stdio::from(writer), 0)
    }
}

/// Parse an `Accepted publickey … ssh2: <TYPE>-CERT <FP> ID <key id> (serial <n>) CA
/// <TYPE> <CA FP>` log line (as testkit's oracle does).
pub fn parse_accepted_cert(line: &str) -> Option<heimdall_testkit::sshd::AcceptedCert> {
    let tail = &line[line.find("ssh2: ")? + "ssh2: ".len()..];
    let mut f = tail.split_whitespace();
    let key_type = f.next()?.to_owned();
    if !key_type.ends_with("-CERT") {
        return None;
    }
    let fingerprint = f.next()?.to_owned();
    let rest = tail.split_once(" ID ")?.1;
    let (key_id, rest) = rest.split_once(" (serial ")?;
    let (serial, rest) = rest.split_once(')')?;
    let mut ca = rest.split_whitespace();
    if ca.next()? != "CA" {
        return None;
    }
    let _ = ca.next()?;
    Some(heimdall_testkit::sshd::AcceptedCert {
        key_type,
        fingerprint,
        key_id: key_id.to_owned(),
        serial: serial.trim().parse().ok()?,
        ca_fingerprint: ca.next()?.to_owned(),
    })
}

/// `testcfg::PRODUCT_FILE_PREFIX` (the binary crate's constant is not importable).
fn heimdall_product_file_prefix() -> &'static str {
    "product-file:"
}

/// Owner-only (Unix).
pub fn owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Windows: the DPAPI directory created by the test (marker first), K_ca put in it for
/// the installation's environment. Unreachable elsewhere.
fn product_file_put(
    dir: &Path,
    db: &Path,
    fp: &CaFingerprint,
    ca: &SecretCaKey,
) -> heimdall_issuer::store::StoreItemRef {
    #[cfg(windows)]
    {
        let env = Store::open(db, Arc::new(NoFaults))
            .unwrap()
            .transaction(|tx| tx.self_environment())
            .unwrap()
            .expect("the runtime recorded its environment");
        heimdall_issuer::store::test_product::create(dir).expect("create the DPAPI test store");
        heimdall_issuer::store::test_product::open(dir, &env)
            .expect("a DPAPI store")
            .put(fp, ca)
            .unwrap()
    }
    #[cfg(not(windows))]
    {
        let _ = (dir, db, fp, ca);
        unreachable!("the product-file store is Windows-only in this suite")
    }
}

/// ⟨A03 lock driver⟩ Windows, the product configuration: K_ca put through the product's
/// own DPAPI store code at the location the release issuer child reads,
/// `<hh>/state/issuer/<environment>` (`m03_cmd::issuer_store` with `HEIMDALL_HOME`
/// set); returns that directory and the item. Unreachable elsewhere.
fn product_put(
    base: &Path,
    db: &Path,
    fp: &CaFingerprint,
    ca: &SecretCaKey,
) -> (PathBuf, heimdall_issuer::store::StoreItemRef) {
    #[cfg(windows)]
    {
        let env = Store::open(db, Arc::new(NoFaults))
            .unwrap()
            .transaction(|tx| tx.self_environment())
            .unwrap()
            .expect("the runtime recorded its environment");
        let dir = base.join(env.as_str());
        let item = heimdall_issuer::store::WindowsDpapi::in_dir(&dir, &env)
            .put(fp, ca)
            .expect("K_ca into the product DPAPI store");
        (dir, item)
    }
    #[cfg(not(windows))]
    {
        let _ = (base, db, fp, ca);
        unreachable!("the product configuration is Windows-only in this suite")
    }
}

/// The version line of the client the runtime resolves (the enrollment evidence names
/// it, so the freshness rules see the current client).
fn client_version_line() -> String {
    Command::new(openssh("ssh"))
        .arg("-V")
        .stdin(Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stderr).trim().to_owned())
        .unwrap_or_default()
}

/// The seeded `verified` enrollment of pair `i` (module docs), with what the runtime
/// rebuilds a verification's plan from: the hash of the line `cert-authority,principals=
/// "<principal>" <CA public key> <marker>` and the existing access's endpoint.
fn enrollment(
    i: usize,
    p: &Pair,
    (ca, ca_public): (&CaFingerprint, &str),
    identity: &IdentityId,
    existing_endpoint: &str,
    client: &str,
    now: Timestamp,
) -> EnrollmentRecord {
    let n = u8::try_from(i + 1).unwrap();
    let id = EnrollmentId::from_random_bytes([0x60 + n; 16]);
    let marker = marker_for(&id);
    let line = format!(
        "cert-authority,principals=\"{}\" {ca_public} {marker}",
        p.principal()
    );
    let account = AccountName::parse(&p.account).unwrap();
    // `[127.0.0.1]:<port> ssh-ed25519 <base64>`.
    let mut words = p.sshd.host_key_line.split_whitespace().skip(1);
    let algorithm = words.next().unwrap().to_owned();
    let key = words.next().unwrap().to_owned();
    EnrollmentRecord {
        marker,
        id,
        destination: DestinationId::parse(&p.destination).unwrap(),
        account: account.clone(),
        ca_fingerprint: ca.clone(),
        form: EnrollmentForm::Account,
        registry: RegistryRef {
            path_display: "~/.ssh/authorized_keys".into(),
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        registry_canonical: RegistryCanonical {
            path: None,
            resolved_by: RegistryResolvedBy::RemoteHome,
        },
        line_sha256: heimdall_domain::projection::Sha256Hex::of(line.as_bytes())
            .as_str()
            .to_owned(),
        target: ApprovedTarget {
            hostname: p.sshd.host.clone(),
            port: p.sshd.port,
            user: account,
            proxy: NoProxy::None,
            host_key: ApprovedHostKey {
                algorithm,
                key,
                fingerprint: "SHA256:fixture".into(),
            },
        },
        existing_access: ExistingAccessRecord {
            identity: identity.clone(),
            endpoint: Some(heimdall_app::enrollment::endpoint_ref(existing_endpoint)),
            public_key_file: None,
        },
        hold: None,
        removal_origin: None,
        late_write: None,
        state: EnrollmentState::Verified,
        verified_at: Some(now),
        evidence: Some(EnrollmentEvidence {
            client: client.to_owned(),
            server: "SSH-2.0-OpenSSH_fixture".into(),
            operation: OperationId::from_random_bytes([0x60 + n; 16]),
            verified_at: now,
            fresh_until: now.checked_add(Duration::from_secs(30 * 86_400)).unwrap(),
            clock: None,
        }),
        created_at: now,
        updated_at: now,
    }
}

/// ⟨M03 wave 6, Windows⟩ What the in-box OpenSSH for Windows client needs in its environment
/// just to start: without `ProgramData`, `ssh.exe` (9.5.6.4) exits 255 before it prints
/// anything, even for `ssh -G`. This was bisected on the PC on 2026-11-18: adding
/// `ProgramData` alone to the World's minimal login or runtime environment gives exit 0, and
/// removing it from a full environment gives 255. The World's minimal Windows environments
/// (its runtime, whose verification `ssh` inherits it, its logins and its `ssh-add -L`
/// probes) carry exactly these, by name, beyond their own, never the whole environment (the
/// orchestrator's ruling on the E2 Windows failures). The product side, a runtime started
/// with a stripped environment, is M04 U2's.
#[cfg(windows)]
pub const OPENSSH_STARTUP_ENV: [&str; 1] = ["ProgramData"];

/// [`OPENSSH_STARTUP_ENV`] read from this process's environment (an absent one is skipped).
#[cfg(windows)]
pub fn openssh_startup_env() -> Vec<(&'static str, OsString)> {
    OPENSSH_STARTUP_ENV
        .iter()
        .filter_map(|k| std::env::var_os(k).map(|v| (*k, v)))
        .collect()
}
