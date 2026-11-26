//! ⟨M06 W5 w5e, w5j; D1; ADR-0006 §18.9 items 5 and 6⟩ A25, the limited roles from the
//! product client (`a25.rs` calls [`journey`] once the viewer and the requester have joined).
//! Every positive step is the real `heimdall` as the limited client's own controller, whose
//! record of the runner says `viewer` or `requester` (the record is **seeded**:
//! `environment join` on a pseudo-terminal is another unit's).
//!
//! * `limited-product-view`: each limited device's `environment status <env>` opens a
//!   management session and shows the runner's own view (a read-only form);
//! * `limited-product-request`: the requester device's `access ensure --environment <env>`,
//!   through its own runtime, is admitted by the runner and answers pending; that device
//!   records nothing. The viewer device's same command is refused on the controller
//!   (`role_insufficient`);
//! * `requester-no-owner-record`: the owner's controller, with its issuer and its record
//!   of the runner, running its hosted passes, holds no record that covers the requester's
//!   grant: it signs nothing, and the request stays pending;
//! * `requester-owner-record`: the owner's standing policy naming the runner (record
//!   source (b), approved on a terminal) covers it: the grant is signed under that record,
//!   and the requester's `operation wait` reads the result;
//! * `limited-owner-forms`: every form the role table gives to the owner alone
//!   (`heimdall_remote::roles::classify` over every request example of `schemas/examples`
//!   and every revision-6 form of the contract golden: nothing is picked by hand) is sent by
//!   each limited client on its own session, and each is refused, one by one, with no effect;
//! * `limited-rotate-endpoint`: `rotate_endpoint` reaches the runner's per-request check
//!   from a limited session (it is on the base capability); the runner refuses it here
//!   because these invitations did not admit Iroh, never for a missing capability;
//! * `limited-product-cli`: an owner command (`update`, `revoke-client`, `invite`,
//!   `recheck`) is refused on the controller, `role_insufficient`; `environment remove`
//!   forgets the record locally without the revoke and says an owner must still revoke the
//!   client, which still authenticates at the runner;
//! * `owner-record-limited-key`: the same key under a record that says `owner` is refused at
//!   the hello (`role_insufficient`): an owner record never works over a limited session.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use heimdall_app::remote_env::{SessionCapabilities, SessionStanding};
use heimdall_contract::controller_record::{ManagementHop, ManagementRoute, RemoteEnvironmentPin};
use heimdall_contract::envelope::Envelope;
use heimdall_contract::ids::{
    AccountName, ClientId, DestinationId, EnvironmentId, GrantId, KeyFingerprint,
};
use heimdall_contract::ipc::capability;
use heimdall_contract::remote::{Permission, Role};
use heimdall_contract::request::{AccessPairRef, Request};
use heimdall_credential::mgmt::{MgmtKey, MgmtKeyStore as _};
use heimdall_domain::time::Clock as _;
use heimdall_remote::roles::{NoConsents, classify};
use heimdall_store::{NoFaults, Store};
use heimdall_testkit::home::Scratch;
use serde_json::Value;

use super::super::m06::{observe, runner_stderr};
use super::super::world::{
    ControllerRuntime, MgmtClient, client_hello, host_key, on_terminal, pending_grant, state_db,
};
use super::{CASE, Peer, World, inspect, refusal};

/// Keep `key` in a fixture store file under `scratch`, for the product controller that
/// stands for its device. Returns the file.
pub(super) fn store_key(scratch: &Scratch, tag: &str, key: &MgmtKey) -> PathBuf {
    let file = scratch.subdir(tag).unwrap().join("k_mgmt.fixture");
    heimdall_credential::mgmt::fixture::FixtureMgmtStore::file(file.clone())
        .put(key)
        .unwrap();
    file
}

/// One joined limited client.
pub(super) struct Limited<'a> {
    pub(super) peer: &'a Peer,
    pub(super) client: &'a ClientId,
    pub(super) role: Role,
    /// Its K_mgmt in a fixture store file ([`store_key`]).
    pub(super) store: &'a Path,
}

/// The owner: its session key, its client, and its own controller installation (stopped).
pub(super) struct Owner<'a> {
    pub(super) peer: &'a Peer,
    pub(super) client: &'a ClientId,
    pub(super) controller: ControllerRuntime,
}

/// One device's product controller, run with **both** fixture key stores: K_mgmt's (the
/// installation's own, `ControllerRuntime::command`) and a scratch K_iroh store of its
/// own, so no process of it can reach a platform key store.
struct Device {
    controller: ControllerRuntime,
    iroh: PathBuf,
}

impl Device {
    fn new(w: &World, tag: &str, controller: ControllerRuntime) -> Device {
        Device {
            controller,
            iroh: w.scratch.subdir(&format!("{tag}i")).unwrap(),
        }
    }

    fn environment(&self) -> Vec<(&'static str, String)> {
        let path = |p: &Path| p.to_string_lossy().into_owned();
        vec![
            ("HOME", path(&self.controller.account)),
            ("HEIMDALL_HOME", path(&self.controller.home)),
            ("HEIMDALL_TEST_SSH_HOME", path(&self.controller.account)),
            ("HEIMDALL_TEST_TIME_SYNC", "synchronized".to_owned()),
            ("HEIMDALL_TEST_SECRET_STORE", "scratch".to_owned()),
            (
                "HEIMDALL_TEST_MGMT_STORE",
                format!("fixture-file:{}", self.controller.mgmt.display()),
            ),
            ("HEIMDALL_TEST_IROH_KEY_STORE", path(&self.iroh)),
        ]
    }

    fn command(&self) -> Command {
        let mut cmd = self.controller.command();
        cmd.env("HEIMDALL_TEST_IROH_KEY_STORE", &self.iroh);
        cmd
    }

    /// `heimdall --json <args>`: the envelope.
    fn json(&self, args: &[&str]) -> Value {
        let out = self.command().arg("--json").args(args).output().unwrap();
        serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
            panic!(
                "{args:?}: {} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
        })
    }

    /// `heimdall <args>` without `--json`: the exit code and what a person reads.
    fn human(&self, args: &[&str]) -> (Option<i32>, String) {
        let out = self.command().args(args).output().unwrap();
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    /// `heimdall --json <args>` on a pseudo-terminal, answering `answer`.
    fn attended(&self, args: &[&str], answer: &str) -> (i32, Value) {
        on_terminal(
            &self.controller.home,
            &self.environment(),
            args,
            Some(answer),
        )
    }

    /// Start this device's runtime (`service run`) and wait until it answers.
    fn start(&mut self) {
        assert!(self.controller.runtime.is_none());
        let child = self
            .command()
            .args(["service", "run"])
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(self.controller.account.join("runtime.stderr")).unwrap())
            .spawn()
            .unwrap();
        self.controller.runtime = Some(child);
        let start = Instant::now();
        while !self
            .command()
            .args(["--json", "service", "status"])
            .output()
            .unwrap()
            .status
            .success()
        {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "the device's runtime did not start: {}",
                self.controller.stderr()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Stop the runtime this test started, through its own handle.
    fn stop(&mut self) {
        if let Some(mut child) = self.controller.runtime.take() {
            let _ = self.command().args(["service", "stop"]).output();
            let start = Instant::now();
            while start.elapsed() < Duration::from_secs(30) {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// This device's entry for `environment` in `environment status --json`.
    fn entry(&self, environment: &str) -> Value {
        let report = self.json(&["environment", "status"]);
        report["data"]["environments"]
            .as_array()
            .and_then(|all| {
                all.iter()
                    .find(|e| e["environment"] == environment)
                    .cloned()
            })
            .unwrap_or_else(|| panic!("no entry for the runner: {report}"))
    }

    /// What this device's store records for `grant` on the runner: its delivered-grant
    /// records (all of them) and the grant's issuance entries.
    fn recorded(&self, grant: &GrantId) -> (usize, usize) {
        let store =
            Store::open_read_only(&state_db(&self.controller.home), Arc::new(NoFaults)).unwrap();
        store
            .transaction(|tx| {
                Ok((
                    tx.delivered_grants(None)?.len(),
                    tx.issuance_entries(grant)?.len(),
                ))
            })
            .unwrap()
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The hello the product's session opener sends for a record whose role is `role`.
fn product_hello(role: Role) -> heimdall_contract::ipc::ClientHello {
    let caps = SessionCapabilities::of(
        SessionStanding::of_record(role),
        heimdall_ipc::session::server_capabilities(),
    );
    let mut hello = client_hello(false);
    hello.capabilities = caps.offered;
    hello.required = caps.required;
    hello
}

/// Every request form this repository has an example of: `schemas/examples/request.*.json`
/// and every row of the revision-6 contract golden (which its own test proves complete
/// against the schema).
fn every_form() -> Vec<(String, Request)> {
    let root = heimdall_testkit::repo::repo_root();
    let mut out = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(root.join("schemas/examples"))
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("request.") && n.ends_with(".json"))
        .collect();
    names.sort();
    for name in names {
        let text = std::fs::read_to_string(root.join("schemas/examples").join(&name)).unwrap();
        let request = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        out.push((name, request));
    }
    let golden: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("tests/contracts/golden/rev6-requests.golden.json"))
            .unwrap(),
    )
    .unwrap();
    for list in ["requests", "no_capability_requests"] {
        for row in golden[list].as_array().unwrap() {
            let what = row["what"].as_str().unwrap().to_owned();
            let request = serde_json::from_value(row["json"].clone())
                .unwrap_or_else(|e| panic!("{what}: {e}"));
            out.push((what, request));
        }
    }
    out
}

/// The forms of [`every_form`] whose permission, in the role table, the owner alone holds.
fn owner_forms() -> Vec<(String, Request, Permission)> {
    every_form()
        .into_iter()
        .filter_map(|(what, request)| {
            let permission = classify(&request, &NoConsents).permission;
            ([Role::Viewer, Role::Requester]
                .iter()
                .all(|r| !r.has(permission))
                && Role::Owner.has(permission))
            .then_some((what, request, permission))
        })
        .collect()
}

fn assert_refused(what: &str, role: Role, answer: &Envelope<Value>, w: &World) {
    assert!(
        !answer.code.is_success(),
        "a {role:?} was served the owner form {what}: {answer:?}\n{}",
        runner_stderr(&w.runner)
    );
    let effect = &answer.data["error"]["effect_status"];
    assert!(
        effect.is_null() || effect == "none",
        "{what} as {role:?}: an effect was reported: {answer:?}"
    );
}

/// A controller installation whose record of the runner says `role` for `client`, with the
/// K_mgmt of the fixture store file `store`. Not started: the commands write or read
/// directly.
fn install(
    w: &World,
    tag: &str,
    seed: u8,
    limited: &Limited<'_>,
    role: Role,
) -> (ControllerRuntime, EnvironmentId) {
    let controller = ControllerRuntime {
        home: w.scratch.subdir(&format!("{tag}h")).unwrap(),
        account: w.scratch.subdir(&format!("{tag}a")).unwrap(),
        mgmt: limited.store.to_path_buf(),
        runtime: None,
    };
    let paths = heimdall_runtime::Paths::under(&controller.home);
    paths.ensure().unwrap();
    let environment = EnvironmentId::parse(&w.environment).unwrap();
    let pin = RemoteEnvironmentPin {
        environment: environment.clone(),
        destination: DestinationId::parse("runner1").unwrap(),
        route: ManagementRoute {
            runner: ManagementHop {
                hostname: w.sshd.host.clone(),
                port: Some(w.sshd.port),
                account: AccountName::parse(&w.account).unwrap(),
                host_keys: vec![host_key(&w.sshd)],
            },
            jump: None,
        },
        client: limited.client.clone(),
        role,
        key_fingerprint: KeyFingerprint::parse(&limited.peer.fingerprint).unwrap(),
        label: None,
        pinned_at: heimdall_runtime::platform::SystemClock.wall(),
    };
    let store = Store::open(
        &heimdall_store::layout::db_path(&paths.state_dir).unwrap(),
        Arc::new(NoFaults),
    )
    .unwrap();
    store
        .transaction(|tx| {
            tx.init_self_environment(&EnvironmentId::from_random_bytes([seed; 16]))?;
            tx.put_remote_environment_pin(
                &pin.environment,
                &pin.destination,
                &pin.route.runner.account,
                &pin.key_fingerprint,
                &serde_json::to_string(&pin).unwrap(),
                pin.pinned_at,
            )
        })
        .unwrap();
    (controller, environment)
}

/// `code` and reason of a `--json` command's envelope.
fn cli_refusal(v: &Value) -> (String, String) {
    (
        v["code"].as_str().unwrap_or("none").to_owned(),
        v["data"]["error"]["reason"]
            .as_str()
            .unwrap_or("none")
            .to_owned(),
    )
}

async fn open(w: &World, limited: &Limited<'_>) -> (MgmtClient, tokio::process::Child) {
    let (session, child) = w
        .session_with(limited.peer, product_hello(limited.role))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "the product's hello for a {:?} record was refused: {e}\n{}",
                limited.role,
                runner_stderr(&w.runner)
            )
        });
    assert_eq!(session.server().role, Some(limited.role));
    assert_eq!(
        session.server().remote_client.as_ref(),
        Some(limited.client)
    );
    for owner_capability in [capability::REMOTE_CONTROL_V1, capability::RUNNER_V1] {
        assert!(
            !session.server().capabilities.contains(owner_capability),
            "a {:?} negotiated {owner_capability}",
            limited.role
        );
    }
    (session, child)
}

/// The runner's authority report, read over a fresh session of the owner's key: the grants
/// it lists as waiting for their issuer, and the grants it holds a certificate for.
async fn runner_report(w: &World, owner: &Peer) -> (Vec<String>, Vec<String>) {
    // (Offering `runner/1`, which the runner grants an owner's session.)
    let (mut session, _child) = w
        .session_with(owner, client_hello(true))
        .await
        .unwrap_or_else(|e| panic!("{e}"));
    let report = session
        .request(
            serde_json::from_value(serde_json::json!({
                "op": "runner", "action": "authority_report",
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(report.code.as_str(), "OK", "{report:?}");
    let grants = |list: &str| -> Vec<String> {
        report.data[list]
            .as_array()
            .into_iter()
            .flatten()
            .map(|g| g["grant"].as_str().unwrap().to_owned())
            .collect()
    };
    (grants("pending_grants"), grants("certificates"))
}

/// The block (module docs). `owner` is the owner's key, client and controller
/// installation; `pair` the pair the runner's profile and policy hold.
#[allow(clippy::too_many_lines)]
pub(super) async fn journey(
    w: &World,
    viewer: &Limited<'_>,
    requester: &Limited<'_>,
    owner: Owner<'_>,
    pair: &AccessPairRef,
) {
    let lines_before = std::fs::read_to_string(&w.keys_file).unwrap();
    let pair_text = format!("{}:{}", pair.destination.as_str(), pair.account.as_str());
    let Owner {
        peer: owner_peer,
        client: owner_client,
        controller: owner_controller,
    } = owner;
    let mut owner_device = Device::new(w, "oc", owner_controller);

    // The two limited devices: the real controller binary, its record seeded.
    let (controller, environment) = install(w, "lv", 0xb1, viewer, viewer.role);
    let mut viewer_device = Device::new(w, "lv", controller);
    let (controller, _) = install(w, "lr", 0xb2, requester, requester.role);
    let mut requester_device = Device::new(w, "lr", controller);
    let env = environment.as_str();

    // limited-product-view: `environment status <env>` opens a session and shows the
    // runner's own view. The record's own lines answer from this device.
    let mut views = Vec::new();
    for (device, limited) in [(&viewer_device, viewer), (&requester_device, requester)] {
        let role = serde_json::to_value(limited.role).unwrap();
        let status = device.json(&["environment", "status", env]);
        assert_eq!(status["code"], "OK", "{status}");
        let entry = &status["data"]["environments"][0];
        assert_eq!(entry["role"], role, "{status}");
        assert_eq!(
            entry["runner_view"]["read"],
            true,
            "the runner's view was not read: {status}\n{}",
            runner_stderr(&w.runner)
        );
        assert_eq!(
            entry["runner_view"]["view"]["environment_id"], w.environment,
            "{status}"
        );
        let (code, text) = device.human(&["environment", "status", env]);
        assert_eq!(code, Some(0), "{text}");
        assert!(
            text.contains("runner's view (read over this device's session)")
                && text.contains(&w.environment),
            "{text}"
        );
        // The list form opens no session: the record alone.
        let list = device.json(&["environment", "status"]);
        assert!(
            list["data"]["environments"][0].get("runner_view").is_none(),
            "{list}"
        );
        views.push(format!("{}=read", role.as_str().unwrap()));
    }
    assert_eq!(std::fs::read_to_string(&w.keys_file).unwrap(), lines_before);
    observe(
        CASE,
        "limited-product-view",
        format!(
            "through=product_cli record=seeded command=environment_status_env {} \
             form=inspect_environments list_form_session=none lines_written=0",
            views.join(" ")
        ),
    );

    // limited-product-request: the requester device's `access ensure --environment`,
    // through its own runtime. No CA is named; nothing is recorded on that device.
    let ensure = |request: &str| {
        [
            "access",
            "ensure",
            "--environment",
            env,
            "--profile",
            "runner-profile",
            "--pair",
            pair_text.as_str(),
            "--work-id",
            "job-a25-requester",
            "--for",
            "10m",
            "--request-id",
            request,
        ]
        .map(str::to_owned)
    };
    let args = |list: &[String]| -> Vec<String> { list.to_vec() };
    let run = |device: &Device, list: &[String]| {
        let list = args(list);
        let refs: Vec<&str> = list.iter().map(String::as_str).collect();
        device.json(&refs)
    };
    requester_device.start();
    viewer_device.start();
    let submitted = run(&requester_device, &ensure("a25-requester-1"));
    assert_eq!(
        submitted["code"],
        "ACCEPTED",
        "the requester's request did not stay pending: {submitted}\n{}\n{}",
        requester_device.controller.stderr(),
        runner_stderr(&w.runner)
    );
    let grant = pending_grant(&submitted);
    let operation = submitted["operation_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the pending answer names no operation: {submitted}"))
        .to_owned();
    assert!(
        submitted["data"]["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("owner controller")),
        "{submitted}"
    );
    assert_eq!(requester_device.recorded(&grant), (0, 0));
    // A viewer's same command is refused on its own controller: nothing is sent.
    let by_viewer = run(&viewer_device, &ensure("a25-viewer-1"));
    assert_eq!(
        cli_refusal(&by_viewer),
        (
            "CAPABILITY_UNAVAILABLE".to_owned(),
            "role_insufficient".to_owned()
        ),
        "{by_viewer}"
    );
    viewer_device.stop();
    let (pending, certified) = runner_report(w, owner_peer).await;
    assert!(pending.contains(&grant.as_str().to_owned()), "{pending:?}");
    assert!(
        !certified.contains(&grant.as_str().to_owned()),
        "{certified:?}"
    );
    observe(
        CASE,
        "limited-product-request",
        "through=product_cli record=seeded command=access_ensure_environment \
         requester=ACCEPTED_pending refresh_dependency=controller ca_named=none \
         requester_delivered_records=0 runner_grant=pending \
         viewer=CAPABILITY_UNAVAILABLE reason=role_insufficient refused_at=controller",
    );

    // requester-no-owner-record: the owner's controller, with its issuer, resynchronizes
    // and runs its passes. It holds no record that covers the grant, so it signs nothing.
    owner_device.start();
    let start = Instant::now();
    loop {
        let entry = owner_device.entry(env);
        if entry["connectivity"]["state"] == "connected" && entry["issuance"] == "reconciled" {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "the owner's controller did not resynchronize: {entry}\n{}",
            owner_device.controller.stderr()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    // (The pass that opened the barrier read a report listing the grant; give its
    // issuance step time to have run.)
    tokio::time::sleep(Duration::from_secs(3)).await;
    let again = run(&requester_device, &ensure("a25-requester-1"));
    assert_eq!(pending_grant(&again), grant, "{again}");
    assert_eq!(
        owner_device.recorded(&grant),
        (0, 0),
        "a requester's pending request was recorded or signed with no owner record"
    );
    assert_eq!(requester_device.recorded(&grant), (0, 0));
    let (pending, certified) = runner_report(w, owner_peer).await;
    assert!(pending.contains(&grant.as_str().to_owned()), "{pending:?}");
    assert!(
        !certified.contains(&grant.as_str().to_owned()),
        "a certificate was installed for it: {certified:?}"
    );
    let entry = owner_device.entry(env);
    assert!(entry.get("issuance_failures").is_none(), "{entry}");
    observe(
        CASE,
        "requester-no-owner-record",
        "owner_controller=issuer_and_owner_record policy_naming_runner=none \
         hosted_pass=reconciled owner_delivered_records=0 issuance_entries=0 \
         runner_certificates_for_grant=0 requester_replay=ACCEPTED_pending",
    );

    // requester-owner-record: the owner's standing policy naming the runner, approved on
    // a terminal (record source (b)). The next hosted pass signs under that record, and
    // the requester's `operation wait` reads the result.
    let (code, allowed) = owner_device.attended(
        &[
            "access",
            "allow",
            "--profile",
            "runner-profile",
            "--environment",
            env,
        ],
        "yes",
    );
    assert_eq!(allowed["code"], "OK", "exit {code}: {allowed}");
    let waited = requester_device
        .command()
        .args(["--json", "operation", "wait", &operation])
        .args(["--timeout-ms", "120000"])
        .output()
        .unwrap();
    let waited: Value = serde_json::from_slice(&waited.stdout).unwrap_or_else(|_| {
        panic!(
            "{} {}",
            String::from_utf8_lossy(&waited.stdout),
            String::from_utf8_lossy(&waited.stderr)
        )
    });
    assert!(
        matches!(waited["code"].as_str(), Some("OK" | "ACCESS_READY")),
        "{waited}\n{}\n{}\n{}",
        owner_device.controller.stderr(),
        requester_device.controller.stderr(),
        runner_stderr(&w.runner)
    );
    let ready = match waited["data"].get("result") {
        Some(result) => result.clone(),
        None => waited["data"].clone(),
    };
    assert_eq!(ready["grant_id"], grant.as_str(), "{waited}");
    assert_eq!(ready["credential_mechanism"], "managed_certificate");
    owner_device.stop();
    requester_device.stop();
    {
        let store =
            Store::open_read_only(&state_db(&owner_device.controller.home), Arc::new(NoFaults))
                .unwrap();
        let records = store
            .transaction(|tx| tx.delivered_grants(Some(&environment)))
            .unwrap();
        // (The policy also covers the owner's own earlier pending grant of the same pair,
        // the `collision` step's: every record here is one the owner's policy wrote.)
        let record = records
            .iter()
            .find(|r| r.grant == grant)
            .unwrap_or_else(|| panic!("no owner record for the grant: {records:?}"));
        assert!(
            records.iter().all(|r| r.policy.is_some()),
            "an owner record that is not from its own policy: {records:?}"
        );
        assert_eq!(record.pairs, [pair.clone()].into_iter().collect());
    }
    assert!(owner_device.recorded(&grant).1 >= 1);
    assert_eq!(
        requester_device.recorded(&grant),
        (0, 0),
        "the requester's device recorded or signed something"
    );
    observe(
        CASE,
        "requester-owner-record",
        "owner_policy_naming_runner=approved_on_terminal record_source=b \
         owner_record_for_grant=from_its_policy signed_under=owner_policy \
         requester_operation_wait=ready \
         mechanism=managed_certificate requester_delivered_records=0",
    );

    // limited-owner-forms: the session level, with the hello the product's opener sends.
    let lines_now = std::fs::read_to_string(&w.keys_file).unwrap();
    let (mut viewer_session, _viewer_child) = open(w, viewer).await;
    let (mut requester_session, _requester_child) = open(w, requester).await;
    let forms = owner_forms();
    let permissions: std::collections::BTreeSet<String> =
        forms.iter().map(|(_, _, p)| format!("{p:?}")).collect();
    for permission in [
        Permission::Approve,
        Permission::IssuerTrust,
        Permission::Enroll,
        Permission::Service,
        Permission::TimeSource,
    ] {
        assert!(
            permissions.contains(&format!("{permission:?}")),
            "no owner form of {permission:?} was enumerated"
        );
    }
    let mut how: BTreeMap<String, usize> = BTreeMap::new();
    for (what, request, _) in &forms {
        for (role, session) in [
            (Role::Viewer, &mut viewer_session),
            (Role::Requester, &mut requester_session),
        ] {
            let answer = session
                .request(request.clone())
                .await
                .unwrap_or_else(|e| panic!("{what} as {role:?}: {e}"));
            assert_refused(what, role, &answer, w);
            let (code, reason) = refusal(&answer);
            *how.entry(format!("{code}/{reason}")).or_default() += 1;
        }
    }
    // Both sessions still serve what their role allows, and nothing was written.
    let read = viewer_session.request(inspect()).await.unwrap();
    assert_eq!(read.code.as_str(), "OK", "{read:?}");
    let read = requester_session.request(inspect()).await.unwrap();
    assert_eq!(read.code.as_str(), "OK", "{read:?}");
    assert_eq!(std::fs::read_to_string(&w.keys_file).unwrap(), lines_now);
    observe(
        CASE,
        "limited-owner-forms",
        format!(
            "owner_forms={} from=role_table sent_by=viewer,requester served=0 refusals={} \
             lines_written=0",
            forms.len(),
            how.iter()
                .map(|(k, n)| format!("{k}:{n}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    );

    // limited-rotate-endpoint: on the base capability, so it reaches the runner's own
    // check for this client. These invitations did not admit Iroh: refused for that.
    let rotate: Request = serde_json::from_value(serde_json::json!({
        "op": "remote_environment", "action": "rotate_endpoint",
        "environment": w.environment, "endpoint": "ab".repeat(32),
    }))
    .unwrap();
    let mut rotated = Vec::new();
    for (role, session) in [
        (Role::Viewer, &mut viewer_session),
        (Role::Requester, &mut requester_session),
    ] {
        let answer = session.request(rotate.clone()).await.unwrap();
        let (code, reason) = refusal(&answer);
        assert_ne!(
            code, "SCHEMA_UNSUPPORTED",
            "{role:?}: rotate_endpoint needed a capability: {answer:?}"
        );
        assert_ne!(reason, "role_insufficient", "{role:?}: {answer:?}");
        assert_eq!(code, "USAGE_ERROR", "{role:?}: {answer:?}");
        let effect = &answer.data["error"]["effect_status"];
        assert!(effect.is_null() || effect == "none", "{answer:?}");
        rotated.push(format!("{role:?}={code}").to_lowercase());
    }
    observe(
        CASE,
        "limited-rotate-endpoint",
        format!(
            "capability=base reached=per_request_check {} why=invitation_without_iroh_admission \
             effect=none",
            rotated.join(" ")
        ),
    );
    drop(viewer_session);
    drop(requester_session);

    // limited-product-cli: owner commands are refused on the controller, from the
    // record; `remove` forgets locally, without the revoke.
    let new_key = MgmtKey::generate().unwrap().public().unwrap().openssh_line;
    let mut cli = Vec::new();
    for (device, limited) in [(&viewer_device, viewer), (&requester_device, requester)] {
        let role = serde_json::to_value(limited.role).unwrap();
        let mut refused = Vec::new();
        for args in [
            vec!["environment", "update", env],
            vec!["environment", "revoke-client", env, owner_client.as_str()],
            vec![
                "environment",
                "invite",
                env,
                "--role",
                "viewer",
                "--public-key",
                new_key.as_str(),
            ],
            vec!["environment", "recheck", env],
        ] {
            let answer = device.json(&args);
            assert_eq!(
                cli_refusal(&answer),
                (
                    "CAPABILITY_UNAVAILABLE".to_owned(),
                    "role_insufficient".to_owned()
                ),
                "{args:?}: {answer}"
            );
            refused.push(format!("{}=role_insufficient", args[1].replace('-', "_")));
        }
        // Nothing was forgotten or written by the refusals.
        let status = device.json(&["environment", "status"]);
        assert_eq!(status["data"]["environments"][0]["role"], role, "{status}");
        assert_eq!(std::fs::read_to_string(&w.keys_file).unwrap(), lines_now);

        // `remove`: forgotten on this device only; the output says who must revoke.
        let (code, text) = device.human(&["environment", "remove", env]);
        assert_eq!(code, Some(0), "{text}");
        assert!(
            text.contains("an owner must still revoke it there")
                && text.contains(limited.client.as_str())
                && text.contains("on this device only"),
            "{text}"
        );
        let status = device.json(&["environment", "status"]);
        assert_eq!(
            status["data"]["environments"],
            serde_json::json!([]),
            "{status}"
        );
        // Again: there is no record left.
        let again = device.json(&["environment", "remove", env]);
        assert_eq!(again["code"], "NOT_FOUND", "{again}");
        // The runner kept the client's line, and the key still authenticates there.
        assert_eq!(std::fs::read_to_string(&w.keys_file).unwrap(), lines_now);
        let (still, _child) = open(w, limited).await;
        drop(still);
        cli.push(format!(
            "{}:{},remove=forgotten_locally,revoke_sent=false,still_enrolled=true",
            role.as_str().unwrap(),
            refused.join(",")
        ));
    }
    // The JSON form of the same outcome (a fresh seeded record).
    let (controller, _) = install(w, "lj", 0xb5, viewer, viewer.role);
    let json_device = Device::new(w, "lj", controller);
    let removed = json_device.json(&["environment", "remove", env]);
    assert_eq!(removed["code"], "OK", "{removed}");
    assert_eq!(removed["data"]["removed"], env, "{removed}");
    assert_eq!(removed["data"]["revoked_on_runner"], false, "{removed}");
    assert_eq!(
        removed["data"]["client"],
        viewer.client.as_str(),
        "{removed}"
    );
    observe(
        CASE,
        "limited-product-cli",
        format!(
            "record=seeded refused_at=controller {} lines_written=0",
            cli.join(" ")
        ),
    );

    // owner-record-limited-key: a record that says owner, over the viewer's key.
    let (controller, environment) = install(w, "lo", 0xb3, viewer, Role::Owner);
    let wrong = Device::new(w, "lo", controller);
    let answer = wrong.json(&["environment", "update", environment.as_str()]);
    assert_eq!(
        cli_refusal(&answer),
        (
            "CAPABILITY_UNAVAILABLE".to_owned(),
            "role_insufficient".to_owned()
        ),
        "an owner record's session without remote-control/1 was used: {answer}\n{}",
        runner_stderr(&w.runner)
    );
    observe(
        CASE,
        "owner-record-limited-key",
        "record=seeded_owner key=viewer environment_update=CAPABILITY_UNAVAILABLE \
         reason=role_insufficient refused_at=hello",
    );
}
