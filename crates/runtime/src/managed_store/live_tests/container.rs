//! ⟨M04 U5⟩ ADR-0010 §4, live and **engine-free**: the local Linux-container binding recipe
//! through the real `Operations`, managed adapter, [`StoreSources`], `ManagedEffectsImpl`,
//! signer table and `EndpointRegistry` of [`super::Live`] (a real signing endpoint on a Unix
//! socket in a scratch runtime directory). No container engine is involved; the mounted flow
//! that needs one is `tests/e2e/container_m04.rs` (`a15_container_mounted_flow`).
//!
//! The container host rule (ADR-0010 §4 item 7: a Linux-native runtime only) is satisfied by
//! the effects' **test switch** (`ManagedEffectsImpl::with_test_container_host`,
//! `Opts::container_host`), so these cases run on macOS and on the devbox alike.
//!
//! * [`container_environment_requests_refusals_and_the_decision_flow`]: the refusal table
//!   (non-owner, non-Linux host, bad label, duplicate label, unknown and own environment) and
//!   the decision (pending, coalesced, denied, approved) with `inspect environments`.
//! * [`one_binding_per_container_environment_busy_continue_and_replacement_at_the_same_path`]:
//!   `environment_busy`, an equivalent `ensure` continuing at the same path, a replacement
//!   binding after the first ended, the old generation's teardown leaving the new socket and
//!   files, the directory's exact contents and the result's mount instruction.
//! * [`a15_container_remove_cleans_only_owned_entries`]: `container remove` with a foreign
//!   entry planted in the directory.

use super::*;
use heimdall_app::Attendance;
use heimdall_contract::environment::EnvironmentRequest;
use heimdall_contract::ids::DecisionId;
use heimdall_contract::request::{DecideRequest, InspectRequest, InspectSubject, Verdict};
use heimdall_domain::decision::{DecisionKind, DecisionState};
use std::path::{Path, PathBuf};

pub(super) fn attended() -> Caller {
    Caller {
        context: CallerContext {
            principal: PrincipalRef::UnixUser { uid: 501 },
            role: ClientRole::Owner,
        },
        attendance: Attendance::Attended { since: t0() },
        interaction: InteractionMode::Interactive,
    }
}

pub(super) fn consumer() -> Caller {
    Caller::unattended(CallerContext {
        principal: PrincipalRef::UnixUser { uid: 501 },
        role: ClientRole::LimitedConsumer,
    })
}

fn host_on() -> Opts {
    Opts {
        container_host: true,
        ..Opts::default()
    }
}

/// `container_add` as the owner: the pending decision it answers with.
async fn add_decision(p: &Process, label: &str) -> DecisionId {
    let e = p
        .ops
        .environment_request(
            &caller(),
            EnvironmentRequest::ContainerAdd {
                label: label.to_owned(),
            },
        )
        .await
        .expect_err("container_add answers with a decision");
    assert_eq!(e.code, Code::InteractionRequired, "{}", e.message);
    DecisionId::parse(e.next.decision_ref.as_deref().expect("a decision ref")).unwrap()
}

pub(super) async fn decide(p: &Process, id: &DecisionId, verdict: Verdict) -> serde_json::Value {
    p.ops
        .decide(
            &attended(),
            DecideRequest {
                decision_id: id.clone(),
                verdict,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("decide: {} {}", e.code, e.message))
        .data
}

/// The container environment the approval created, with its directory tag.
pub(super) fn container_rows(w: &Live) -> Vec<heimdall_domain::environment::ManagedEnvironment> {
    w.store.transaction(|tx| tx.managed_environments()).unwrap()
}

/// An approved container environment `label`: its ID and host directory.
async fn approved(w: &Live, p: &Process, label: &str) -> (EnvironmentId, PathBuf) {
    let d = add_decision(p, label).await;
    let data = decide(p, &d, Verdict::Approve).await;
    let id = EnvironmentId::parse(data["environment"]["environment_id"].as_str().unwrap()).unwrap();
    let dir = PathBuf::from(
        data["environment"]["realization"]["directory"]
            .as_str()
            .unwrap(),
    );
    assert!(container_rows(w).iter().any(|r| r.environment == id));
    (id, dir)
}

/// Let `environment` serve ensures of profile `dev` without a decision: automatic activation
/// (the approval grants `managed_signing` only) and the standing policy extended to it.
pub(super) fn permit_ensures(w: &Live, environment: &EnvironmentId) {
    w.store
        .transaction(|tx| {
            let mut rec = tx
                .environment(environment)?
                .expect("the environment record");
            rec.permissions.automatic_activation = true;
            tx.upsert_environment(&rec)?;
            let mut pol = tx.policy(&PolicyId::parse("pol").unwrap())?.unwrap();
            pol.environments.insert(environment.clone());
            pol.revision = PolicyRevision(pol.revision.0 + 1);
            tx.upsert_policy(&pol, false)
        })
        .unwrap();
}

pub(super) async fn ensure_in(
    p: &Process,
    environment: &EnvironmentId,
    work: &str,
    request: &str,
) -> Result<EnsureData, heimdall_app::OpError> {
    p.ops
        .ensure(
            &caller(),
            EnsureRequest {
                profile: Some(ProfileId::parse("dev").unwrap()),
                profile_revision: None,
                scope: pairs().into_iter().collect(),
                environment: Some(environment.clone()),
                work_id: WorkId::parse(work).unwrap(),
                until: None,
                required_capabilities: RequiredCapabilities::default(),
                request_id: RequestId::parse(request).unwrap(),
                interaction: InteractionMode::Interactive,
                wait: WaitMode::Sync { timeout_ms: 30_000 },
                connection: None,
                context: None,
                covered_only: false,
            },
        )
        .await
        .map(|c| c.data)
}

/// ⟨M04 I-28⟩ The result's `endpoint_kind_not_covered` entries: each field and the endpoint
/// kind it names.
pub(super) fn claim_reasons(
    d: &EnsureData,
) -> Vec<(
    String,
    Option<heimdall_contract::managed::BindingEndpointKind>,
)> {
    d.evidence
        .iter()
        .filter(|x| x.source == heimdall_contract::managed::EvidenceSource::EndpointKindNotCovered)
        .map(|x| (x.field.clone(), x.endpoint_kind))
        .collect()
}

/// ⟨M04 I-28⟩ One reason per claim-table field, each naming `kind`.
pub(super) fn reasons_naming(
    kind: heimdall_contract::managed::BindingEndpointKind,
) -> Vec<(
    String,
    Option<heimdall_contract::managed::BindingEndpointKind>,
)> {
    heimdall_adapters::managed::report::CLAIM_TABLE_FIELDS
        .iter()
        .map(|f| ((*f).to_owned(), Some(kind)))
        .collect()
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn socket_of(dir: &Path) -> String {
    dir.join("agent.sock").to_string_lossy().into_owned()
}

pub(super) fn operations_recorded(w: &Live) -> u64 {
    w.store
        .transaction(|tx| tx.table_counts())
        .unwrap()
        .operations
}

pub(super) fn decisions_pending(w: &Live) -> usize {
    w.store
        .transaction(|tx| tx.pending_decisions())
        .unwrap()
        .len()
}

pub(super) async fn inspect_environments(p: &Process, as_caller: &Caller) -> serde_json::Value {
    p.ops
        .inspect(
            as_caller,
            InspectRequest {
                subject: InspectSubject::Environments,
                preview: None,
                cwd: None,
                redact: false,
            },
        )
        .await
        .unwrap()
        .data
}

/// The refusal table of `environment_request` and the `AddEnvironment` decision: each refusal
/// writes nothing; an equal pending request is joined; a denial writes nothing but the
/// decision's state; an approval creates the row, the record and the directory (0700), and
/// `inspect environments` lists it for the owner (and only the M01 answer for another role).
#[tokio::test]
async fn container_environment_requests_refusals_and_the_decision_flow() {
    use std::os::unix::fs::PermissionsExt as _;
    let w = Live::new();
    let p = w.process_opts(Arc::new(NoStageHook), host_on()).await;
    let unknown = EnvironmentId::from_random_bytes([0xaa; 16]);
    let remove = |id: &EnvironmentId| EnvironmentRequest::ContainerRemove {
        environment_id: id.clone(),
    };
    let add = |label: &str| EnvironmentRequest::ContainerAdd {
        label: label.to_owned(),
    };

    // ⟨M04 U4b⟩ The Mode B rows run in processes with a WSL host (`q`: a bridge supervisor,
    // `r`: a host and no supervisor), beside the container rows in the bare process `p`.
    let (q, _host, _factory) = super::wsl_mode_b::process(&w, true).await;
    let (r, _host_r, _factory_r) = super::wsl_mode_b::process(&w, false).await;
    let g = super::wsl_mode_b::guid();
    let wsl = |guid: &heimdall_contract::environment::DistributionGuid,
               account: &str,
               a: bool,
               b: bool| EnvironmentRequest::WslEnable {
        distribution_guid: guid.clone(),
        account: account.to_owned(),
        mode_a: a,
        mode_b: b,
    };

    // The refusal table: (process, who, request, code, reason). Nothing is written by any row.
    let rows: Vec<(&Process, Caller, EnvironmentRequest, Code, Option<&str>)> = vec![
        (
            &p,
            consumer(),
            add("lab"),
            Code::CapabilityUnavailable,
            None,
        ),
        (
            &p,
            consumer(),
            remove(&unknown),
            Code::CapabilityUnavailable,
            None,
        ),
        (&p, caller(), add(""), Code::UsageError, None),
        (&p, caller(), add(&"x".repeat(65)), Code::UsageError, None),
        (&p, caller(), add("a\nb"), Code::UsageError, None),
        (&p, caller(), remove(&unknown), Code::NotFound, None),
        (&p, caller(), remove(&env()), Code::NotFound, None),
        // Mode B: the owner role first, then the host, the account and the registration, then
        // the supervisor (a runtime with a host and no supervisor realizes no Mode B).
        (
            &q,
            consumer(),
            wsl(&g, "ubuntu", false, true),
            Code::CapabilityUnavailable,
            None,
        ),
        (
            &p,
            caller(),
            wsl(&g, "ubuntu", false, true),
            Code::CapabilityUnavailable,
            Some("wsl_unavailable"),
        ),
        (
            &q,
            caller(),
            wsl(&g, "a b", false, true),
            Code::UsageError,
            None,
        ),
        (
            &q,
            caller(),
            wsl(&super::wsl_mode_b::other_guid(), "ubuntu", false, true),
            Code::NotFound,
            Some("wsl_distribution_unknown"),
        ),
        (
            &r,
            caller(),
            wsl(&g, "ubuntu", false, true),
            Code::CapabilityUnavailable,
            Some("driver_unavailable"),
        ),
    ];
    let (ops0, dec0) = (operations_recorded(&w), decisions_pending(&w));
    for (process, who, request, code, reason) in rows {
        let e = process
            .ops
            .environment_request(&who, request.clone())
            .await
            .expect_err(&format!("{request:?}"));
        assert_eq!(
            (e.code, e.reason.as_deref()),
            (code, reason),
            "{request:?}: {}",
            e.message
        );
    }
    q.shutdown.cancel();
    r.shutdown.cancel();
    assert_eq!(
        (
            operations_recorded(&w),
            decisions_pending(&w),
            container_rows(&w).len()
        ),
        (ops0, dec0, 0),
        "no refusal wrote anything"
    );
    // The WSL forms: served by U3b (below).
    let e = p
        .ops
        .environment_request(
            &caller(),
            EnvironmentRequest::WslDisable {
                distribution_guid: heimdall_contract::environment::DistributionGuid::parse(
                    "0b1c2d3e-4f50-6172-8394-a5b6c7d8e9f0",
                )
                .unwrap(),
                start: false,
            },
        )
        .await
        .unwrap_err();
    // ⟨M04 U3b⟩ The WSL forms are served now: a runtime without a WSL host refuses them
    // `wsl_unavailable`, before anything is written.
    assert_eq!(
        (e.code, e.reason.as_deref()),
        (Code::CapabilityUnavailable, Some("wsl_unavailable"))
    );
    // A host that is not Linux, with no test switch, refuses before anything is read (a
    // Linux host realizes containers, so that row is for the other platforms).
    if cfg!(not(target_os = "linux")) {
        let q = w.process(Arc::new(NoStageHook)).await;
        let e = q
            .ops
            .environment_request(&caller(), add("lab"))
            .await
            .unwrap_err();
        assert_eq!(
            (e.code, e.reason.as_deref()),
            (Code::CapabilityUnavailable, Some("driver_unavailable"))
        );
        assert!(e.message.contains("Linux-native"), "{}", e.message);
        assert_eq!(decisions_pending(&w), dec0, "the host check came first");
        q.shutdown.cancel();
    }

    // Pending, coalesced: the same label joins the one decision; its record carries the
    // disclosures and a random directory tag, never one derived from the label.
    let d = add_decision(&p, "lab").await;
    assert_eq!(
        add_decision(&p, "lab").await,
        d,
        "an equal pending request is joined"
    );
    assert_eq!(decisions_pending(&w), 1);
    let rec = w.store.transaction(|tx| tx.decision(&d)).unwrap().unwrap();
    let DecisionKind::AddEnvironment {
        realization:
            heimdall_domain::environment::EnvironmentRealization::Container { label, dir_tag },
        disclosures,
        ..
    } = &rec.kind
    else {
        panic!("not an AddEnvironment: {:?}", rec.kind);
    };
    assert_eq!(label, "lab");
    assert_eq!(dir_tag.len(), 16);
    assert!(
        dir_tag
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    assert_eq!(
        disclosures,
        &heimdall_domain::environment::EnvironmentDisclosure::CONTAINER.to_vec()
    );
    assert!(
        container_rows(&w).is_empty(),
        "a pending decision creates nothing"
    );

    // Denied: the decision is consumed, nothing else is written.
    let counts = w.store.transaction(|tx| tx.table_counts()).unwrap();
    decide(&p, &d, Verdict::Deny).await;
    assert_eq!(
        w.store
            .transaction(|tx| tx.decision(&d))
            .unwrap()
            .unwrap()
            .state,
        DecisionState::Denied
    );
    assert!(container_rows(&w).is_empty());
    assert!(
        w.store
            .transaction(|tx| tx.environment(&env()))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        w.store
            .transaction(|tx| tx.table_counts())
            .unwrap()
            .operations,
        counts.operations
    );
    assert!(
        !w.run_dir().join("c").exists(),
        "a denial creates no directory"
    );

    // Approved: the row, the record (`managed_signing` and nothing else), the directory.
    let (id, dir) = approved(&w, &p, "lab").await;
    let row = container_rows(&w).pop().unwrap();
    assert_eq!(
        row.state,
        heimdall_domain::environment::ManagedState::Active
    );
    assert_eq!(row.controller, env());
    let record = w
        .store
        .transaction(|tx| tx.environment(&id))
        .unwrap()
        .unwrap();
    assert_eq!(record.kind, EnvironmentKind::Container);
    assert_eq!(record.label.as_deref(), Some("lab"));
    assert_eq!(
        record.permissions,
        EnvironmentPermissions {
            automatic_activation: false,
            managed_signing: true,
            issuer_access: false,
        }
    );
    assert!(dir.starts_with(w.run_dir().join("c")), "{dir:?}");
    assert_eq!(
        std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(
        entries(&dir).is_empty(),
        "no binding yet: nothing in the directory"
    );
    // A second container with the same label is a usage error while the first is in the set.
    let e = p
        .ops
        .environment_request(&caller(), add("lab"))
        .await
        .unwrap_err();
    assert_eq!(e.code, Code::UsageError, "{}", e.message);

    // `inspect environments`: the owner sees every environment (its own first); another role
    // sees M01's answer only.
    let owner = inspect_environments(&p, &caller()).await;
    let items = owner["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["kind"], "native_session");
    assert_eq!(items[0]["environment_id"], env().as_str());
    assert_eq!(items[1]["kind"], "container");
    assert_eq!(items[1]["state"], "active");
    assert_eq!(items[1]["label"], "lab");
    assert_eq!(items[1]["realization"]["directory"], dir.to_str().unwrap());
    assert_eq!(
        items[1]["realization"]["in_container_path"],
        "/run/heimdall"
    );
    let other = inspect_environments(&p, &consumer()).await;
    assert!(other.get("items").is_none(), "{other}");
    assert_eq!(other["environment_id"], env().as_str());
    p.shutdown.cancel();
}

/// ADR-0010 §4 items 2, 3, 4 and 6 through the real pipeline: one active binding per
/// container environment (`environment_busy` for another work, nothing written), the same
/// work continuing at the same path, a replacement after the first binding ended, the old
/// generation's teardown leaving the new socket and files, exactly the expected directory
/// entries, the endpoint listing only the binding's identities, and the result's mount
/// instruction (no host path in the native fields).
#[tokio::test]
async fn one_binding_per_container_environment_busy_continue_and_replacement_at_the_same_path() {
    let w = Live::new();
    let p = w.process_opts(Arc::new(NoStageHook), host_on()).await;
    let (id, dir) = approved(&w, &p, "lab").await;
    permit_ensures(&w, &id);
    let expected = |certs: &[&str]| -> Vec<String> {
        let mut v: Vec<String> = [
            ".generation",
            "agent.sock",
            "key.pub",
            "known_hosts",
            "ssh_config",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .chain(certs.iter().map(|c| (*c).to_owned()))
        .collect();
        v.sort();
        v
    };
    let certs = ["cert-h1.pub", "cert-h2.pub"];

    // Work A: the binding's endpoint and files appear in the environment's stable directory.
    let a = ensure_in(&p, &id, "w-a", "r-a")
        .await
        .unwrap_or_else(|e| panic!("ensure a: {} {}", e.code, e.message));
    assert_eq!(
        a.environment_id, id,
        "the binding is pinned to its environment"
    );
    assert_eq!(
        entries(&dir),
        expected(&certs),
        "exactly the expected entries"
    );
    assert_eq!(
        listed(&socket_of(&dir)).await.unwrap(),
        2,
        "its two certificates, nothing else"
    );
    // The mount instruction: no host path in the native fields.
    let c = &a.consumer;
    assert_eq!(c.signing_endpoint, None);
    assert_eq!(c.ssh_config_include, None);
    let r = c.realization.as_ref().expect("a realization descriptor");
    assert_eq!(r.endpoint.as_deref(), Some("/run/heimdall/agent.sock"));
    assert_eq!(r.config.as_deref(), Some("/run/heimdall/ssh_config"));
    let m = r.mount.as_ref().unwrap();
    assert_eq!(
        (m.source.as_str(), m.target.as_str(), m.read_only),
        (dir.to_str().unwrap(), "/run/heimdall", true)
    );
    assert!(r.environment.contains(&(
        "SSH_AUTH_SOCK".to_owned(),
        "/run/heimdall/agent.sock".to_owned()
    )));
    assert!(c.pairs.iter().all(|p| {
        p.endpoint
            .as_ref()
            .is_none_or(|e| e.locator == "/run/heimdall/agent.sock")
    }));
    // The rendered files: in-container paths only, the approved key as the only trust.
    let config = std::fs::read_to_string(dir.join("ssh_config")).unwrap();
    assert!(config.contains("StrictHostKeyChecking yes"), "{config}");
    assert!(config.contains("IdentityAgent \"/run/heimdall/agent.sock\""));
    assert!(config.contains("IdentityFile \"/run/heimdall/cert-h1.pub\""));
    assert!(config.contains("Host h1\n") && config.contains("HostName h1.example.invalid"));
    assert!(!config.to_ascii_lowercase().contains("forwardagent"));
    assert!(
        !config.contains(w.run_dir().to_str().unwrap()),
        "no host path in the container's file"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("known_hosts")).unwrap(),
        "h1.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture\nh2.example.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIhostfixture\n"
    );
    // No key but the public one, and nothing of the control or issuer endpoints.
    assert!(
        !entries(&dir)
            .iter()
            .any(|n| n.contains("signing") || n.contains("issuer"))
    );

    // Another work in the same environment: busy, and nothing is written.
    let (ops_before, before) = (operations_recorded(&w), entries(&dir));
    let e = ensure_in(&p, &id, "w-b", "r-b").await.unwrap_err();
    assert_eq!(
        (e.code, e.reason.as_deref()),
        (Code::ConfigConflict, Some("environment_busy")),
        "{}",
        e.message
    );
    assert_eq!(
        operations_recorded(&w),
        ops_before,
        "no operation recorded for the refusal"
    );
    assert_eq!(entries(&dir), before, "the directory is untouched");
    assert_eq!(
        listed(&socket_of(&dir)).await.unwrap(),
        2,
        "binding A still serves"
    );

    // The same request again is the existing idempotent replay: the same binding, nothing
    // new written.
    let replay = ensure_in(&p, &id, "w-a", "r-a").await.unwrap();
    assert_eq!(replay.binding_id, a.binding_id);
    assert_eq!(
        operations_recorded(&w),
        ops_before,
        "a replay records no operation"
    );
    // The same work with a new request ID (equivalent: same work, profile and scope) is
    // admitted; its binding takes the directory over, so the container keeps one path.
    let a2 = ensure_in(&p, &id, "w-a", "r-a2")
        .await
        .unwrap_or_else(|e| panic!("ensure a2: {} {}", e.code, e.message));
    assert_ne!(a2.binding_id, a.binding_id);
    assert_eq!(entries(&dir), expected(&certs));
    assert_eq!(listed(&socket_of(&dir)).await.unwrap(), 2);
    let marker = std::fs::read_to_string(dir.join(".generation")).unwrap();
    assert!(
        marker.trim_end().ends_with(a2.binding_id.as_str()),
        "{marker}"
    );

    // Both bindings end (released): a different work is admitted, and its endpoint and files
    // appear at the same path.
    for b in [&a.binding_id, &a2.binding_id] {
        p.ops
            .release(
                &caller(),
                heimdall_contract::request::ReleaseRequest {
                    binding_id: b.clone(),
                },
            )
            .await
            .unwrap_or_else(|e| panic!("release: {} {}", e.code, e.message));
    }
    let b = ensure_in(&p, &id, "w-b", "r-b2")
        .await
        .unwrap_or_else(|e| panic!("ensure b after the release: {} {}", e.code, e.message));
    assert_ne!(b.binding_id, a.binding_id);
    assert_eq!(
        b.consumer
            .realization
            .as_ref()
            .and_then(|r| r.mount.as_ref())
            .map(|m| m.source.clone()),
        Some(dir.to_string_lossy().into_owned()),
        "the replacement is mounted at the same host directory"
    );
    assert_eq!(entries(&dir), expected(&certs));
    let mut served = false;
    for _ in 0..100 {
        if listed(&socket_of(&dir)).await == Ok(2) {
            served = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(served, "the replacement binding serves at the same path");
    let marker = std::fs::read_to_string(dir.join(".generation")).unwrap();
    assert!(
        marker.trim_end().ends_with(b.binding_id.as_str()),
        "{marker}"
    );

    // The old generation's teardown (a late cleanup of binding A at generation 1) leaves the
    // replacement's socket and files alone.
    heimdall_app::ports::ManagedEffects::clear(&p.effects, &a.binding_id, 1).unwrap();
    assert_eq!(
        entries(&dir),
        expected(&certs),
        "the replacement's files stay"
    );
    assert_eq!(
        listed(&socket_of(&dir)).await.unwrap(),
        2,
        "the replacement's socket stays"
    );
    p.shutdown.cancel();
}

/// `container remove` through the real runtime with a foreign file planted in the directory:
/// the environment leaves the set (its grant ends, the endpoint stops), the entries Heimdall
/// wrote are removed through the quarantine, the foreign entry is left and reported, and the
/// directory stays until it is empty; a second remove answers `OK` with nothing removed; a
/// removed environment is refused as a target.
#[tokio::test]
async fn a15_container_remove_cleans_only_owned_entries() {
    let w = Live::new();
    let p = w.process_opts(Arc::new(NoStageHook), host_on()).await;
    let (id, dir) = approved(&w, &p, "lab").await;
    permit_ensures(&w, &id);
    let a = ensure_in(&p, &id, "w-a", "r-a")
        .await
        .unwrap_or_else(|e| panic!("ensure: {} {}", e.code, e.message));
    std::fs::write(dir.join("notes.txt"), b"keep me").unwrap();
    assert!(listed(&socket_of(&dir)).await.is_ok());

    let remove = || EnvironmentRequest::ContainerRemove {
        environment_id: id.clone(),
    };
    let done = p
        .ops
        .environment_request(&caller(), remove())
        .await
        .unwrap_or_else(|e| panic!("remove: {} {}", e.code, e.message))
        .data;
    assert_eq!(done["environment"]["state"], "removed");
    assert_eq!(done["left_in_place"], serde_json::json!(["notes.txt"]));
    assert_eq!(
        entries(&dir),
        vec!["notes.txt".to_owned()],
        "only the foreign entry remains"
    );
    assert_eq!(std::fs::read(dir.join("notes.txt")).unwrap(), b"keep me");
    assert!(
        gone(&socket_of(&dir)).await,
        "nothing serves the path any more"
    );
    assert!(p.registry.binding_endpoint(&a.binding_id).is_none());
    // The grant ended through the withdrawal path.
    let mut ended = false;
    for _ in 0..200 {
        let g = w
            .store
            .transaction(|tx| tx.grant(&a.grant_id))
            .unwrap()
            .unwrap();
        if !g.state.permits_use() {
            ended = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(ended, "the environment's grant ended");
    // Idempotent: a second remove is `OK` and removes nothing (the foreign entry is still
    // reported); once the foreign entry is gone the directory goes too.
    let again = p
        .ops
        .environment_request(&caller(), remove())
        .await
        .unwrap()
        .data;
    assert_eq!(again["environment"]["state"], "removed");
    assert_eq!(again["left_in_place"], serde_json::json!(["notes.txt"]));
    std::fs::remove_file(dir.join("notes.txt")).unwrap();
    let last = p
        .ops
        .environment_request(&caller(), remove())
        .await
        .unwrap()
        .data;
    assert!(last.get("left_in_place").is_none(), "{last}");
    assert!(!dir.exists(), "an empty directory is removed");
    // A removed environment is refused as a target; it stays in `inspect environments`.
    let e = ensure_in(&p, &id, "w-c", "r-c").await.unwrap_err();
    assert_eq!(
        (e.code, e.reason.as_deref()),
        (Code::NotFound, Some("environment_removed"))
    );
    let listing = inspect_environments(&p, &caller()).await;
    assert_eq!(listing["items"][1]["state"], "removed");
    p.shutdown.cancel();
}

/// ⟨M04 I-28⟩ The claim gate's endpoint kind comes from the grant's environment, through the
/// grant's recorded terms: a container binding's result carries one
/// `endpoint_kind_not_covered` reason per claim-table field naming `container` and no
/// claim-table entry, and a native binding's result in the same runtime carries no reason.
/// (The report on a qualifying host is `integration_managed_adapter`'s
/// `container_binding_reads_every_claim_field_unknown_on_a_qualifying_linux_host`.)
#[tokio::test]
async fn a15_container_binding_result_names_its_endpoint_kind_for_the_claim_table() {
    let w = Live::new();
    let p = w.process_opts(Arc::new(NoStageHook), host_on()).await;
    let native = w
        .ensure(&p, "native", RequiredCapabilities::default())
        .await
        .unwrap_or_else(|e| panic!("native ensure: {} {}", e.code, e.message));
    assert_eq!(
        claim_reasons(&native),
        vec![],
        "a native binding has no reason"
    );
    let (id, _) = approved(&w, &p, "lab").await;
    permit_ensures(&w, &id);
    let c = ensure_in(&p, &id, "w-c", "r-c")
        .await
        .unwrap_or_else(|e| panic!("container ensure: {} {}", e.code, e.message));
    assert_eq!(c.environment_id, id);
    assert_eq!(
        claim_reasons(&c),
        reasons_naming(heimdall_contract::managed::BindingEndpointKind::Container)
    );
    assert!(
        c.evidence
            .iter()
            .all(|x| x.source != heimdall_contract::managed::EvidenceSource::ClaimTable)
    );
}
