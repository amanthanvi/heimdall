//! ⟨M06 U5a⟩ The route helper's direct and jump legs, failover and the catalog pin at both hops
//! (ADR-0012 §5.2–§5.5; ADR-0010 §5, §9 item 3; m06-plan U5a), against real `ssh` and loopback
//! sshds.
//!
//! **Why `harness = false`.** A helper alias runs `"<program>" route connect …` as its
//! `ProxyCommand`, and the CLI's `route connect` entry is W2's (the runtime does not serve
//! `ResolveRouteBinding` yet). So this binary is also the helper: started as `<this binary>
//! route connect --destination … --account … --endpoint …`, it runs the product's helper core
//! (`heimdall_app::routes::route_connect` with the production `TokioLegDialer`) over a fixture
//! catalog and binding table named by `HM_ROUTE_FIXTURE`, with its standard streams as the
//! client's pipes. libtest would print to standard output, which is the SSH stream here, so
//! this file runs its own cases and prints libtest's lines (`running N tests`, `test … ok`,
//! `test result: …`). Arguments: substring filters, `--exact`, `--list`; other flags are
//! ignored.
//!
//! **Fixtures** (AGENTS.md): every key is generated per run (`FixtureKey`), every agent is a
//! `FakeAgent` in scratch, every server a `LoopbackSshd` on 127.0.0.1 with per-run host keys,
//! and every `ssh` runs with `-F <scratch config>` and `SSH_AUTH_SOCK` removed. The settings
//! this suite is about (the host-trust and multiplexing settings) are set by the scratch
//! configuration, which is P's own rendering. A case that needs a local sshd prints why it is
//! skipped where none can start (Windows: no local sshd with forwarding settings; the helper's
//! native `ProxyCommand` run through the in-box client is a Windows-host row).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines,
    missing_docs
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use heimdall_app::routes::legs::TokioLegDialer;
use heimdall_app::routes::verify::{
    Hop, RouteVerifyError, verify_jump_leg, verify_projected_alias,
};
use heimdall_app::routes::{
    ExpectedProxy, FailoverConfig, FailoverOutcome, HelperArgs, JumpHop, PinExpectation,
    RouteBinding, RouteHelperError, RouteHelperPorts, route_connect, select_route_binding,
};
use heimdall_contract::environment::JumpAccess;
use heimdall_contract::ids::{AccountName, BindingId, DestinationId, GrantId, IdentityId, RouteId};
use heimdall_contract::managed::PreferredMechanism;
use heimdall_contract::route::{
    DestinationRoute, RouteEventKind, RouteFailureClass, RouteHealthPayload, RouteSpec,
};
use heimdall_domain::catalog::{
    ApprovedRoute, DestinationDefinition, DestinationRecord, RouteCatalogView,
};
use heimdall_domain::scope::AccessPair;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FIXTURE_ENV: &str = "HM_ROUTE_FIXTURE";

// --- the fixture catalog (also the helper mode's input) -----------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FixtureBinding {
    binding: BindingId,
    grant: GrantId,
    endpoint: String,
    pairs: Vec<AccessPair>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FixtureHop {
    jump: DestinationId,
    hostname: String,
    port: u16,
    user: String,
    pin_file: String,
    identity_agent: String,
    identity_file: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Fixture {
    destinations: Vec<DestinationRecord>,
    mechanisms: Vec<(AccessPair, PreferredMechanism)>,
    routes: Vec<(DestinationId, Vec<DestinationRoute>)>,
    bindings: Vec<FixtureBinding>,
    hops: Vec<FixtureHop>,
    ssh_client: PathBuf,
    health_log: PathBuf,
}

struct FixturePorts {
    fixture: Fixture,
    health: std::sync::Mutex<Vec<RouteHealthPayload>>,
}

impl FixturePorts {
    fn new(fixture: Fixture) -> Self {
        Self {
            fixture,
            health: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl RouteHelperPorts for FixturePorts {
    async fn resolve_route_binding(
        &self,
        destination: &DestinationId,
        account: &AccountName,
        endpoint: &str,
    ) -> Result<RouteBinding, RouteHelperError> {
        let candidates: Vec<RouteBinding> = self
            .fixture
            .bindings
            .iter()
            .map(|b| RouteBinding {
                binding: b.binding.clone(),
                grant: b.grant.clone(),
                endpoint: b.endpoint.clone(),
                pairs: b.pairs.iter().cloned().collect(),
            })
            .collect();
        let pair = AccessPair {
            destination: destination.clone(),
            account: account.clone(),
        };
        select_route_binding(&candidates, &pair, endpoint)
    }

    async fn route_view(&self) -> Result<RouteCatalogView, RouteHelperError> {
        let mut v = RouteCatalogView::default();
        for d in &self.fixture.destinations {
            v.destinations.insert(d.id.clone(), d.clone());
        }
        for (p, m) in &self.fixture.mechanisms {
            v.mechanisms.insert(p.clone(), *m);
        }
        for (d, r) in &self.fixture.routes {
            v.routes.insert(d.clone(), r.clone());
        }
        Ok(v)
    }

    async fn jump_hop(
        &self,
        route: &ApprovedRoute,
        _access: JumpAccess,
        _binding: &RouteBinding,
    ) -> Result<JumpHop, RouteHelperError> {
        let h = self
            .fixture
            .hops
            .iter()
            .find(|h| h.jump == route.jump)
            .ok_or(RouteHelperError::Unavailable)?;
        Ok(JumpHop {
            alias: route.jump_alias.clone(),
            hostname: h.hostname.clone(),
            port: Some(h.port),
            user: h.user.clone(),
            host_key_alias: format!("hm-dest-{}", route.jump),
            pin_file: h.pin_file.clone(),
            host_key_algorithms: Some("ssh-ed25519".into()),
            identity_agent: h.identity_agent.clone(),
            identity_file: h.identity_file.clone(),
            certificate_file: None,
        })
    }

    async fn record_health(&self, payload: RouteHealthPayload) {
        if !self.fixture.health_log.as_os_str().is_empty() {
            use std::io::Write as _;
            if let Ok(mut f) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.fixture.health_log)
            {
                let _ = writeln!(f, "{}", serde_json::to_string(&payload).unwrap());
            }
        }
        self.health.lock().unwrap().push(payload);
    }
}

// --- helper mode ---------------------------------------------------------------------------

/// `<this binary> route connect …`: the helper, with this process's standard streams as the
/// client's pipes (OpenSSH starts a `ProxyCommand` with two pipes).
#[cfg(unix)]
fn helper_main(args: &[OsString]) -> i32 {
    use std::os::fd::AsFd as _;
    let Some(path) = std::env::var_os(FIXTURE_ENV) else {
        eprintln!("route connect: no fixture");
        return 2;
    };
    let fixture: Fixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let code = rt.block_on(async move {
        let args = match HelperArgs::parse(args.iter().cloned()) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("route connect: {e}");
                return 2;
            }
        };
        let stdin = std::fs::File::from(std::io::stdin().as_fd().try_clone_to_owned().unwrap());
        let stdout = std::fs::File::from(std::io::stdout().as_fd().try_clone_to_owned().unwrap());
        let client_in = tokio::net::unix::pipe::Receiver::from_file(stdin).unwrap();
        let client_out = tokio::net::unix::pipe::Sender::from_file(stdout).unwrap();
        let dialer = TokioLegDialer {
            ssh_client: fixture.ssh_client.clone(),
            relay_jump_stderr: true,
            fill: |_, _| {},
        };
        let ports = FixturePorts::new(fixture);
        let mut stderr = std::io::stderr();
        match route_connect(
            &args,
            &ports,
            &dialer,
            client_in,
            client_out,
            &FailoverConfig::default(),
            &mut stderr,
        )
        .await
        {
            Ok(o) if o.succeeded() => 0,
            Ok(_) => 255,
            Err(e) => {
                eprintln!("route connect: {e}");
                255
            }
        }
    });
    // The client's pipe may stay open: exit without waiting on anything that reads it.
    std::process::exit(code)
}

#[cfg(not(unix))]
fn helper_main(_: &[OsString]) -> i32 {
    eprintln!("route connect: this suite's helper mode ({FIXTURE_ENV}) runs on Unix only");
    2
}

// --- the runner ----------------------------------------------------------------------------

type Case = (&'static str, fn());

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    if args.len() >= 3 && args[1] == "route" && args[2] == "connect" {
        std::process::exit(helper_main(&args[3..]));
    }
    let cases: &[Case] = &[
        (
            "a_server_sending_pre_identification_lines_works",
            a_server_sending_pre_identification_lines_works,
        ),
        (
            "a_client_first_server_times_out_as_identification_timeout_and_the_next_route_is_used",
            a_client_first_server_times_out_as_identification_timeout_and_the_next_route_is_used,
        ),
        (
            "a_late_failure_after_the_forwarding_boundary_is_terminal_and_recorded",
            a_late_failure_after_the_forwarding_boundary_is_terminal_and_recorded,
        ),
        (
            "concurrent_grants_never_borrow_a_jump_pair_and_an_ambiguous_endpoint_is_refused",
            concurrent_grants_never_borrow_a_jump_pair_and_an_ambiguous_endpoint_is_refused,
        ),
        (
            "each_host_pin_defeated_combination_is_refused_by_ssh_g",
            each_host_pin_defeated_combination_is_refused_by_ssh_g,
        ),
        (
            "helper_alias_two_hop_substitution_fails_before_authentication",
            helper_alias_two_hop_substitution_fails_before_authentication,
        ),
    ];
    let exact = args.iter().any(|a| a == "--exact");
    let list = args.iter().any(|a| a == "--list");
    let filters: Vec<String> = args[1..]
        .iter()
        .filter_map(|a| a.to_str())
        .filter(|a| !a.starts_with('-'))
        .map(str::to_owned)
        .collect();
    let selected: Vec<&Case> = cases
        .iter()
        .filter(|(name, _)| {
            filters.is_empty()
                || filters.iter().any(|f| {
                    if exact {
                        name == f
                    } else {
                        name.contains(f.as_str())
                    }
                })
        })
        .collect();
    if list {
        for (name, _) in &selected {
            println!("{name}: test");
        }
        return;
    }
    let started = Instant::now();
    println!("\nrunning {} tests", selected.len());
    let mut failed = Vec::new();
    for (name, case) in &selected {
        let ok = std::panic::catch_unwind(*case).is_ok();
        println!("test {name} ... {}", if ok { "ok" } else { "FAILED" });
        if !ok {
            failed.push(*name);
        }
    }
    if !failed.is_empty() {
        println!("\nfailures:");
        for name in &failed {
            println!("    {name}");
        }
    }
    println!(
        "\ntest result: {}. {} passed; {} failed; 0 ignored; 0 measured; {} filtered out; finished in {:.2}s\n",
        if failed.is_empty() { "ok" } else { "FAILED" },
        selected.len() - failed.len(),
        failed.len(),
        cases.len() - selected.len(),
        started.elapsed().as_secs_f64()
    );
    if !failed.is_empty() {
        std::process::exit(101);
    }
}

// --- shared pieces ---------------------------------------------------------------------------

fn d(s: &str) -> DestinationId {
    DestinationId::parse(s).unwrap()
}

fn rid(n: u8) -> RouteId {
    RouteId::from_random_bytes([n; 16])
}

fn pair(dest: &str, account: &str) -> AccessPair {
    AccessPair {
        destination: d(dest),
        account: AccountName::parse(account).unwrap(),
    }
}

fn destination(id: &str, host: &str, port: u16, account: &str) -> DestinationRecord {
    DestinationRecord {
        id: d(id),
        alias: id.to_owned(),
        revision: 1,
        definition: DestinationDefinition::Managed {
            hostname: host.into(),
            port: Some(port),
            account: AccountName::parse(account).unwrap(),
            identity: IdentityId::from_random_bytes([7; 16]),
            jump: None,
        },
        label: None,
        updated_at: "2026-11-20T12:00:00Z".parse().unwrap(),
    }
}

fn route(n: u8, spec: RouteSpec, ident_ms: Option<u64>) -> DestinationRoute {
    DestinationRoute {
        id: rid(n),
        route: spec,
        exposure: None,
        consents: Vec::new(),
        identification_timeout_ms: ident_ms,
    }
}

fn direct(port: u16) -> RouteSpec {
    RouteSpec::Direct {
        host: "127.0.0.1".into(),
        port: Some(port),
    }
}

/// A port on 127.0.0.1 nothing listens on (bound, then closed).
fn closed_port() -> u16 {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    l.local_addr().unwrap().port()
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A destination `lab` (account `deploy`) with `routes`, one binding at `/e1` covering it.
fn fixture_with(routes: Vec<DestinationRoute>) -> Fixture {
    Fixture {
        destinations: vec![destination("lab", "127.0.0.1", 22, "deploy")],
        routes: vec![(d("lab"), routes)],
        bindings: vec![FixtureBinding {
            binding: BindingId::from_random_bytes([1; 16]),
            grant: GrantId::from_random_bytes([1; 16]),
            endpoint: "/e1".into(),
            pairs: vec![pair("lab", "deploy")],
        }],
        ..Fixture::default()
    }
}

fn args(dest: &str, endpoint: &str) -> HelperArgs {
    HelperArgs {
        destination: d(dest),
        account: AccountName::parse("deploy").unwrap(),
        endpoint: endpoint.into(),
    }
}

/// Run the helper core in process: the client writes `client_bytes`, then reads until EOF.
/// Returns the outcome, what the client received, the diagnostics and the health results.
fn run_helper(
    fixture: Fixture,
    a: &HelperArgs,
    client_bytes: &'static [u8],
) -> (
    Result<FailoverOutcome, RouteHelperError>,
    Vec<u8>,
    String,
    Vec<RouteHealthPayload>,
) {
    rt().block_on(async {
        let ports = FixturePorts::new(fixture);
        let dialer = TokioLegDialer {
            ssh_client: PathBuf::from("/nonexistent/ssh"),
            relay_jump_stderr: false,
            fill: |_, _| {},
        };
        let (client, helper) = tokio::io::duplex(64 * 1024);
        let (helper_in, helper_out) = tokio::io::split(helper);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write.write_all(client_bytes).await.unwrap();
        // The client then ends its side: the echo server closes once it has read it all.
        client_write.shutdown().await.unwrap();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            let _ = client_read.read_to_end(&mut got).await;
            got
        });
        let mut diagnostics: Vec<u8> = Vec::new();
        let result = tokio::time::timeout(
            Duration::from_secs(60),
            route_connect(
                a,
                &ports,
                &dialer,
                helper_in,
                helper_out,
                &FailoverConfig::default(),
                &mut diagnostics,
            ),
        )
        .await
        .expect("the helper ends within its bounds");
        drop(client_write);
        let got = tokio::time::timeout(Duration::from_secs(10), reader)
            .await
            .map(Result::unwrap)
            .unwrap_or_default();
        let health = ports.health.lock().unwrap().clone();
        (
            result,
            got,
            String::from_utf8_lossy(&diagnostics).into_owned(),
            health,
        )
    })
}

/// A loopback server that, per connection, sends `banner` lines, then its identification
/// (unless `silent`), then echoes what it reads until EOF (or resets the connection after the
/// first read when `reset`).
fn spawn_server(
    banner: &'static [&'static str],
    silent: bool,
    reset: bool,
) -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let rt = rt();
        rt.block_on(async move {
            listener.set_nonblocking(true).unwrap();
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            let Ok(Ok((mut s, _))) =
                tokio::time::timeout(Duration::from_secs(30), listener.accept()).await
            else {
                return;
            };
            if silent {
                // A client-first server: waits for the client's identification.
                let mut buf = [0u8; 64];
                let _ = tokio::time::timeout(Duration::from_secs(30), s.read(&mut buf)).await;
                return;
            }
            for line in banner {
                s.write_all(line.as_bytes()).await.unwrap();
            }
            s.write_all(b"SSH-2.0-HmFixture_1\r\n").await.unwrap();
            let mut buf = [0u8; 256];
            loop {
                let n = match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if reset {
                    s.set_zero_linger().unwrap();
                    drop(s);
                    return;
                }
                if s.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
    });
    (port, handle)
}

// --- the cases -------------------------------------------------------------------------------

/// ADR-0012 §5.5 item 1: lines the server sends before its identification are buffered and
/// forwarded unchanged, in order, with the identification; the client's bytes reach the server
/// only after it identified; one `route.health` result names the route used.
fn a_server_sending_pre_identification_lines_works() {
    let (port, server) = spawn_server(
        &["Welcome to the lab\r\n", "Authorized use only\r\n"],
        false,
        false,
    );
    let fixture = fixture_with(vec![route(1, direct(port), None)]);
    let (result, got, _, health) = run_helper(fixture, &args("lab", "/e1"), b"SSH-2.0-client\r\n");
    let outcome = result.unwrap();
    assert!(outcome.succeeded(), "{outcome:?}");
    assert_eq!(
        String::from_utf8_lossy(&got),
        "Welcome to the lab\r\nAuthorized use only\r\nSSH-2.0-HmFixture_1\r\nSSH-2.0-client\r\n",
        "pre-identification lines, the identification, then the echoed client bytes"
    );
    assert_eq!(health.len(), 1);
    assert_eq!(health[0].kind, RouteEventKind::Health);
    assert_eq!(health[0].final_route, Some(rid(1)));
    assert_eq!(health[0].attempts.len(), 1);
    assert_eq!(health[0].attempts[0].failure, None);
    server.join().unwrap();
}

/// ADR-0012 §5.5: a refused route and a client-first server (which never identifies while the
/// helper holds the client's bytes) both fail before the boundary, the latter at its route's
/// bound as `identification_timeout`; the next approved route is used, and the result is
/// `failed_over` with each attempt's class.
fn a_client_first_server_times_out_as_identification_timeout_and_the_next_route_is_used() {
    let refused = closed_port();
    let (silent, silent_server) = spawn_server(&[], true, false);
    let (good, good_server) = spawn_server(&[], false, false);
    let fixture = fixture_with(vec![
        route(1, direct(refused), None),
        route(2, direct(silent), Some(700)),
        route(3, direct(good), None),
    ]);
    let started = Instant::now();
    let (result, got, _, health) = run_helper(fixture, &args("lab", "/e1"), b"SSH-2.0-client\r\n");
    let elapsed = started.elapsed();
    let outcome = result.unwrap();
    assert!(outcome.succeeded(), "{outcome:?}");
    assert!(
        elapsed >= Duration::from_millis(700) && elapsed < Duration::from_secs(8),
        "the identification wait is the route's own bound: {elapsed:?}"
    );
    assert!(got.starts_with(b"SSH-2.0-HmFixture_1\r\n"));
    assert_eq!(health.len(), 1);
    assert_eq!(health[0].kind, RouteEventKind::FailedOver);
    let classes: Vec<_> = health[0]
        .attempts
        .iter()
        .map(|a| (a.route.clone(), a.failure))
        .collect();
    assert_eq!(
        classes,
        [
            (rid(1), Some(RouteFailureClass::Refused)),
            (rid(2), Some(RouteFailureClass::IdentificationTimeout)),
            (rid(3), None),
        ]
    );
    assert_eq!(health[0].final_route, Some(rid(3)));
    silent_server.join().unwrap();
    good_server.join().unwrap();
}

/// ADR-0012 §5.5 item 2: after the first forwarded byte a failure is terminal for the attempt
/// (`terminal_after_forwarding`, recorded in `route.health`), and the next approved route is
/// never tried.
fn a_late_failure_after_the_forwarding_boundary_is_terminal_and_recorded() {
    let (resetting, resetting_server) = spawn_server(&[], false, true);
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let never = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let fixture = fixture_with(vec![
        route(1, direct(resetting), None),
        route(2, direct(never), None),
    ]);
    let (result, got, _, health) = run_helper(fixture, &args("lab", "/e1"), b"SSH-2.0-client\r\n");
    let outcome = result.unwrap();
    assert!(outcome.late_failure, "{outcome:?}");
    assert!(got.starts_with(b"SSH-2.0-HmFixture_1\r\n"));
    assert!(
        matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "the next route was never connected"
    );
    assert_eq!(health.len(), 2, "{health:?}");
    assert_eq!(health[0].final_route, Some(rid(1)));
    assert_eq!(
        health[1]
            .attempts
            .iter()
            .map(|a| a.failure)
            .collect::<Vec<_>>(),
        [Some(RouteFailureClass::TerminalAfterForwarding)]
    );
    assert_eq!(health[1].final_route, Some(rid(1)));
    resetting_server.join().unwrap();
}

/// ADR-0012 §5.4: two concurrent grants on different endpoints. The first grant's binding
/// (final + b1) never uses the second grant's jump pair (b2): that route is not attempted
/// (`route_dependency_out_of_scope`), and with no other route the helper refuses before any
/// connection. An endpoint with two bindings, or none, is `route_binding_ambiguous`.
fn concurrent_grants_never_borrow_a_jump_pair_and_an_ambiguous_endpoint_is_refused() {
    let (good, good_server) = spawn_server(&[], false, false);
    let base = |routes: Vec<DestinationRoute>, bindings: Vec<FixtureBinding>| Fixture {
        destinations: vec![
            destination("lab", "127.0.0.1", 22, "deploy"),
            destination("b1", "127.0.0.1", 22, "jump"),
            destination("b2", "127.0.0.1", 22, "jump"),
        ],
        mechanisms: vec![
            (pair("b1", "jump"), PreferredMechanism::ManagedCertificate),
            (pair("b2", "jump"), PreferredMechanism::ManagedCertificate),
        ],
        routes: vec![(d("lab"), routes)],
        bindings,
        ..Fixture::default()
    };
    let binding = |n: u8, endpoint: &str, pairs: Vec<AccessPair>| FixtureBinding {
        binding: BindingId::from_random_bytes([n; 16]),
        grant: GrantId::from_random_bytes([n; 16]),
        endpoint: endpoint.into(),
        pairs,
    };
    let grants = || {
        vec![
            binding(1, "/e1", vec![pair("lab", "deploy"), pair("b1", "jump")]),
            binding(2, "/e2", vec![pair("lab", "deploy"), pair("b2", "jump")]),
        ]
    };
    // The first grant, routes [jump via b2, direct]: the jump through b2 is not attempted.
    let fixture = base(
        vec![
            route(1, RouteSpec::Jump { via: d("b2") }, None),
            route(2, direct(good), None),
        ],
        grants(),
    );
    let (result, _, diagnostics, health) =
        run_helper(fixture, &args("lab", "/e1"), b"SSH-2.0-c\r\n");
    assert!(result.unwrap().succeeded());
    assert!(
        diagnostics.contains(&format!(
            "route {} not used: route_dependency_out_of_scope",
            rid(1)
        )),
        "{diagnostics}"
    );
    assert_eq!(
        health[0]
            .attempts
            .iter()
            .map(|a| a.route.clone())
            .collect::<Vec<_>>(),
        [rid(2)],
        "only the usable approved route was tried"
    );
    good_server.join().unwrap();
    // Only the jump through b2: refused before any connection.
    let only_b2 = || vec![route(1, RouteSpec::Jump { via: d("b2") }, None)];
    let (result, _, _, health) = run_helper(base(only_b2(), grants()), &args("lab", "/e1"), b"");
    assert_eq!(
        result.unwrap_err(),
        RouteHelperError::NoUsableRoute("route_dependency_out_of_scope")
    );
    assert!(health.is_empty());
    // The second grant's own binding may use it (it is planned; the leg is not dialed here
    // because the fixture has no jump hop, so the helper reports the catalog unavailable).
    let (result, _, _, _) = run_helper(base(only_b2(), grants()), &args("lab", "/e2"), b"");
    assert_eq!(result.unwrap_err(), RouteHelperError::Unavailable);
    // Two bindings at one endpoint, and an endpoint with none: ambiguous.
    let twins = vec![
        binding(1, "/e1", vec![pair("lab", "deploy")]),
        binding(3, "/e1", vec![pair("lab", "deploy")]),
    ];
    let (result, _, _, _) = run_helper(base(only_b2(), twins), &args("lab", "/e1"), b"");
    assert_eq!(result.unwrap_err(), RouteHelperError::BindingAmbiguous);
    let (result, _, _, _) = run_helper(base(only_b2(), grants()), &args("lab", "/e9"), b"");
    let err = result.unwrap_err();
    assert_eq!(err, RouteHelperError::BindingAmbiguous);
    assert_eq!(err.reason(), Some("route_binding_ambiguous"));
}

// --- the `ssh -G` combinations (ADR-0012 §5.2) ----------------------------------------------

fn ssh_client() -> Option<PathBuf> {
    heimdall_testkit::home::find_program("ssh")
}

fn render_helper_p(
    program: &Path,
    pin_file: &Path,
    endpoint: &Path,
    port: u16,
    user: &str,
) -> (String, String) {
    use heimdall_sshconf::render::{
        AliasName, DEFAULT_MANAGED_IDENTITY_FORM, HostName, ManagedAlias, PathStyle, RenderPath,
        Section, render_sections,
    };
    use heimdall_sshconf::routes::{HelperRoute, helper_command};
    let style = if cfg!(windows) {
        PathStyle::Windows
    } else {
        PathStyle::Unix
    };
    let path = |p: &Path| match style {
        PathStyle::Unix => RenderPath::unix(p).unwrap(),
        PathStyle::Windows => RenderPath::windows(p).unwrap(),
    };
    let route = HelperRoute::new(path(program), "final", path(pin_file)).unwrap();
    let endpoint = path(endpoint);
    let command = helper_command(&route, user, &endpoint, style).unwrap();
    let section = Section::Helper {
        route,
        section: Box::new(Section::ExistingAccess(ManagedAlias {
            alias: AliasName::parse("final").unwrap(),
            hostname: HostName::parse("127.0.0.1").unwrap(),
            port: Some(port),
            user: user.to_owned(),
            identity_agent: Some(endpoint),
            identity_files: vec![path(&pin_file.with_file_name("id.pub"))],
            identities_only: true,
        })),
    };
    let p = render_sections(&[section], style, DEFAULT_MANAGED_IDENTITY_FORM).unwrap();
    (String::from_utf8(p).unwrap(), command)
}

/// ADR-0012 §5.2 (m06-plan U5a): with `ssh -G` on the rendered helper alias, each setting
/// that defeats the catalog pin is refused and named, whether it comes from an earlier `Host *`
/// block, an alias override (`Host final`) or a `Match` block: `StrictHostKeyChecking no`
/// **with the pin file effective**, `accept-new`, `ask`, a global known-hosts source, a second
/// user known-hosts file, a `KnownHostsCommand`, `VerifyHostKeyDNS`, `UpdateHostKeys`, another
/// `HostKeyAlias`, another proxy, a master and a foreign `ControlPath`. The binding's own mux
/// path is accepted; a setting after P's block changes nothing. The jump leg's own pins verify.
fn each_host_pin_defeated_combination_is_refused_by_ssh_g() {
    let Some(ssh) = ssh_client() else {
        println!("skipped: no ssh client found");
        return;
    };
    let scratch = heimdall_testkit::home::Scratch::new().unwrap();
    let dir = scratch.path();
    let pin = dir.join("pins");
    let program = dir.join("bin").join("heimdall");
    let endpoint = dir.join("agent.sock");
    let (p, command) = render_helper_p(&program, &pin, &endpoint, 2222, "deploy");
    let expect = |owned: Option<&str>| PinExpectation {
        host_key_alias: "hm-dest-final".into(),
        pin_file: pin.to_string_lossy().replace('\\', "/"),
        owned_control_path: owned.map(str::to_owned),
        proxy: ExpectedProxy::Helper(command.clone()),
    };
    let config = dir.join("ssh_config");
    let rt = rt();
    let check = |before: &str, after: &str, owned: Option<&str>| {
        std::fs::write(&config, format!("{before}\n{p}\n{after}\n")).unwrap();
        rt.block_on(verify_projected_alias(
            &ssh,
            Some(&config),
            "final",
            &expect(owned),
            heimdall_localenv::sys::openssh_env::fill_openssh_environment,
        ))
    };
    assert_eq!(check("", "", None), Ok(()), "P alone verifies");
    assert_eq!(
        check(
            "",
            "Host *\n    StrictHostKeyChecking no\n    ControlPath /tmp/x\n",
            None
        ),
        Ok(()),
        "settings after P's block change nothing"
    );
    let ks = dir.join("kh");
    let cases: Vec<(String, &str)> = vec![
        (
            "Host *\n    StrictHostKeyChecking no".into(),
            "stricthostkeychecking",
        ),
        (
            "Host final\n    StrictHostKeyChecking accept-new".into(),
            "stricthostkeychecking",
        ),
        (
            "Match originalhost final\n    StrictHostKeyChecking ask".into(),
            "stricthostkeychecking",
        ),
        (
            "Host *\n    StrictHostKeyChecking off".into(),
            "stricthostkeychecking",
        ),
        (
            "Host final\n    HostKeyAlias someone-else".into(),
            "hostkeyalias",
        ),
        (
            format!(
                "Host *\n    UserKnownHostsFile \"{}\" \"{}\"",
                pin.display(),
                dir.join("more").display()
            ),
            "userknownhostsfile",
        ),
        (
            "Host *\n    GlobalKnownHostsFile /etc/ssh/ssh_known_hosts".into(),
            "globalknownhostsfile",
        ),
        (
            format!("Host *\n    KnownHostsCommand {} %H", ks.display()),
            "knownhostscommand",
        ),
        (
            "Host *\n    VerifyHostKeyDNS yes".into(),
            "verifyhostkeydns",
        ),
        ("Host *\n    UpdateHostKeys yes".into(), "updatehostkeys"),
        ("Host *\n    ControlMaster auto".into(), "controlmaster"),
        (
            "Host *\n    ControlPath /tmp/hm-foreign-%C".into(),
            "controlpath",
        ),
        (
            "Match originalhost final\n    ProxyCommand nc %h %p".into(),
            "proxycommand",
        ),
        ("Host final\n    ProxyJump elsewhere".into(), "proxycommand"),
    ];
    for (before, setting) in &cases {
        match check(before, "", None) {
            Err(RouteVerifyError::Defeated {
                hop: Hop::Final,
                defeated,
            }) => {
                assert_eq!(defeated.setting, *setting, "{before}");
            }
            other => panic!("{before}: {other:?}"),
        }
    }
    // `StrictHostKeyChecking no` is refused even though the pin file is in use: ssh -G shows
    // the pin file effective and the check still refuses.
    std::fs::write(
        &config,
        format!("Host *\n    StrictHostKeyChecking no\n{p}\n"),
    )
    .unwrap();
    let out = std::process::Command::new(&ssh)
        .args([
            "-F".as_ref(),
            config.as_os_str(),
            "-G".as_ref(),
            "final".as_ref(),
        ])
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.lines()
            .any(|l| l.starts_with("userknownhostsfile ") && l.ends_with("pins")),
        "the pin file is effective"
    );
    assert!(text.lines().any(|l| l == "stricthostkeychecking false"));
    // The binding's own mux path is accepted; any other is not.
    let owned = dir.join("mux").join("final");
    let owned_text = owned.to_string_lossy().replace('\\', "/");
    let before = format!("Host *\n    ControlPath \"{owned_text}\"");
    assert_eq!(check(&before, "", Some(&owned_text)), Ok(()));
    assert!(check(&before, "", Some("/elsewhere")).is_err());
    // The jump hop: the jump leg's own pins verify with this client.
    let hop = JumpHop {
        alias: "bastion".into(),
        hostname: "127.0.0.1".into(),
        port: Some(2200),
        user: "jump".into(),
        host_key_alias: "hm-dest-bastion".into(),
        pin_file: pin.to_string_lossy().replace('\\', "/"),
        host_key_algorithms: Some("ssh-ed25519".into()),
        identity_agent: endpoint.to_string_lossy().replace('\\', "/"),
        identity_file: dir.join("id.pub").to_string_lossy().replace('\\', "/"),
        certificate_file: None,
    };
    assert_eq!(
        rt.block_on(verify_jump_leg(
            &ssh,
            &hop,
            Hop::Jump(0),
            heimdall_localenv::sys::openssh_env::fill_openssh_environment
        )),
        Ok(())
    );
}

// --- M04-D03 extended to helper aliases (ADR-0012 §5.2, §5.4; ADR-0010 §9 item 3) ----------

/// m06-plan U5a: M04-D03's two-hop substitution, through a **helper** alias. The final host
/// has routes [jump via the bastion, direct]; the client's `ssh` reads P's helper alias (the
/// final host's catalog pin) and runs this binary as the helper, whose jump leg pins the
/// bastion's own key with `-F none`. With the client configuration's and the pin file's
/// substitutions:
/// * **control:** both hops authenticate, the session runs through the jump route;
/// * **A, the bastion's pinned key substituted:** the jump leg fails host-key verification
///   before authenticating at the bastion, the final host is never reached, and the helper
///   **does not fail over** to the direct route (a host-key failure is never retried);
/// * **B, the final host's pinned key substituted:** the bastion authenticates and forwards,
///   the client refuses the final host's key before any authentication there;
/// * **C, a user `KnownHostsCommand` serving a wrong key** (after P's block, as M04-D03
///   inherited it): never consulted on either hop (catalog-only trust), the session runs.
fn helper_alias_two_hop_substitution_fails_before_authentication() {
    #[cfg(not(unix))]
    {
        println!(
            "skipped: blocked on a local sshd with forwarding settings (the Windows row is the \
             in-box OpenSSH helper run on a Windows host)"
        );
    }
    #[cfg(unix)]
    two_hop_unix();
}

#[cfg(unix)]
fn two_hop_unix() {
    use heimdall_testkit::agent::{AgentMode, Endpoint, FakeAgent, FakeAgentConfig, FixtureKey};
    use heimdall_testkit::sshd::{LOOPBACK, LoopbackSshd, SshdConfig};
    let Some(ssh) = ssh_client() else {
        println!("skipped: no ssh client found");
        return;
    };
    let scratch = heimdall_testkit::home::Scratch::new().unwrap();
    let key = FixtureKey::generate();
    let canary = key.comment().to_owned();
    let redact = |s: &str| s.replace(&canary, "<fixture-comment>");
    let final_host = match LoopbackSshd::start(
        &scratch,
        SshdConfig {
            authorized: vec![key.public().clone()],
            ..SshdConfig::default()
        },
    ) {
        Ok(s) => s,
        Err(e) => {
            println!("skipped: {e:?}");
            return;
        }
    };
    let jump_host = LoopbackSshd::start(
        &scratch,
        SshdConfig {
            authorized: vec![key.public().clone()],
            tcp_forwarding_permit_open: Some(vec![format!("{LOOPBACK}:{}", final_host.port)]),
            ..SshdConfig::default()
        },
    )
    .unwrap_or_else(|e| panic!("blocked: {e:?}"));
    let account = final_host
        .login_account()
        .expect("the fixture sshd's account");
    let agent = FakeAgent::start(
        Endpoint::in_scratch(&scratch, "a").unwrap(),
        FakeAgentConfig {
            keys: vec![key.clone()],
            mode: AgentMode::Normal,
        },
    );
    let endpoint = PathBuf::from(agent.endpoint().locator());
    let dir = scratch.subdir("r").unwrap();
    let id_pub = dir.join("id.pub");
    std::fs::write(&id_pub, format!("{}\n", key.public_line_without_comment())).unwrap();
    let pin = dir.join("pins");
    let key_of = |line: &str| {
        line.split_whitespace()
            .skip(1)
            .collect::<Vec<_>>()
            .join(" ")
    };
    let (final_key, jump_key) = (
        key_of(&final_host.host_key_line),
        key_of(&jump_host.host_key_line),
    );
    let wrong = || {
        key_of(&format!(
            "x {}",
            FixtureKey::generate().public_line_without_comment()
        ))
    };
    let write_pins = |final_k: &str, jump_k: &str| {
        std::fs::write(
            &pin,
            format!("hm-dest-final {final_k}\nhm-dest-bastion {jump_k}\n"),
        )
        .unwrap();
    };
    write_pins(&final_key, &jump_key);
    let program = std::env::current_exe().unwrap();
    let (p, command) = render_helper_p(&program, &pin, &endpoint, final_host.port, &account);
    let config = dir.join("ssh_config");
    std::fs::write(&config, &p).unwrap();
    // The alias verifies before anything connects (ADR-0012 §5.2).
    let expect = PinExpectation {
        host_key_alias: "hm-dest-final".into(),
        pin_file: pin.to_string_lossy().into_owned(),
        owned_control_path: None,
        proxy: ExpectedProxy::Helper(command),
    };
    assert_eq!(
        rt().block_on(verify_projected_alias(
            &ssh,
            Some(&config),
            "final",
            &expect,
            |_, _| {}
        )),
        Ok(())
    );
    // The helper's fixture catalog: final (routes: jump via bastion, then direct), bastion
    // (existing access: no stored preference), one binding at the alias's endpoint.
    let health_log = dir.join("health.ndjson");
    let mut bastion = destination("bastion", LOOPBACK, jump_host.port, &account);
    bastion.alias = "bastion".into();
    let fixture = Fixture {
        destinations: vec![
            destination("final", LOOPBACK, final_host.port, &account),
            bastion,
        ],
        mechanisms: Vec::new(),
        routes: vec![(
            d("final"),
            vec![
                route(1, RouteSpec::Jump { via: d("bastion") }, None),
                route(2, direct(final_host.port), None),
            ],
        )],
        bindings: vec![FixtureBinding {
            binding: BindingId::from_random_bytes([1; 16]),
            grant: GrantId::from_random_bytes([1; 16]),
            endpoint: endpoint.to_string_lossy().into_owned(),
            pairs: vec![pair("final", &account), pair("bastion", &account)],
        }],
        hops: vec![FixtureHop {
            jump: d("bastion"),
            hostname: LOOPBACK.into(),
            port: jump_host.port,
            user: account.clone(),
            pin_file: pin.to_string_lossy().into_owned(),
            identity_agent: endpoint.to_string_lossy().into_owned(),
            identity_file: id_pub.to_string_lossy().into_owned(),
        }],
        ssh_client: ssh.clone(),
        health_log: health_log.clone(),
    };
    let fixture_path = dir.join("fixture.json");
    std::fs::write(&fixture_path, serde_json::to_vec(&fixture).unwrap()).unwrap();
    let connect = |marker: &str| {
        let _ = std::fs::remove_file(&health_log);
        let mut cmd = std::process::Command::new(&ssh);
        cmd.args(["-F".as_ref(), config.as_os_str()])
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=20",
                "-v",
                "final",
            ])
            .arg(format!("echo {marker}"))
            .env_remove("SSH_AUTH_SOCK")
            .env(FIXTURE_ENV, &fixture_path)
            .stdin(std::process::Stdio::null());
        let out = cmd.output().unwrap();
        let health: Vec<RouteHealthPayload> = std::fs::read_to_string(&health_log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            redact(&String::from_utf8_lossy(&out.stderr)),
            health,
        )
    };
    let attempts = |s: &LoopbackSshd, mark: u64| -> usize {
        [
            "Accepted publickey",
            "Failed publickey",
            "Postponed publickey",
            "Invalid user",
        ]
        .iter()
        .map(|n| s.log_lines_since(mark, n).len())
        .sum()
    };
    let accepted =
        |s: &LoopbackSshd, mark: u64| s.log_lines_since(mark, "Accepted publickey").len();
    let connections =
        |s: &LoopbackSshd, mark: u64| s.log_lines_since(mark, "Connection from").len();

    // The control.
    let (j, f) = (jump_host.log_mark(), final_host.log_mark());
    let (ok, stdout, stderr, health) = connect("hm-u5a-ok");
    assert!(ok && stdout.contains("hm-u5a-ok"), "control: {stderr}");
    assert_eq!(
        accepted(&jump_host, j),
        1,
        "control: the jump leg authenticated"
    );
    assert_eq!(
        accepted(&final_host, f),
        1,
        "control: the final host authenticated"
    );
    assert_eq!(health.len(), 1, "{health:?}");
    assert_eq!(
        health[0].final_route,
        Some(rid(1)),
        "through the jump route"
    );

    // A. the bastion's pinned key substituted: no failover to the direct route.
    write_pins(&final_key, &wrong());
    let (j, f) = (jump_host.log_mark(), final_host.log_mark());
    let (ok, stdout, stderr, health) = connect("hm-u5a-a");
    assert!(!ok && !stdout.contains("hm-u5a-a"));
    assert!(stderr.contains("Host key verification failed"), "{stderr}");
    assert_eq!(
        attempts(&jump_host, j),
        0,
        "no publickey attempt at the substituted bastion"
    );
    assert_eq!(
        connections(&final_host, f),
        0,
        "the final host was never reached by any route"
    );
    assert!(!stderr.contains("Authenticated to"), "{stderr}");
    assert_eq!(health.len(), 1, "{health:?}");
    assert_eq!(health[0].final_route, None);
    assert_eq!(
        health[0]
            .attempts
            .iter()
            .map(|a| a.route.clone())
            .collect::<Vec<_>>(),
        [rid(1)],
        "a host-key failure is never failed over"
    );

    // B. the final host's pinned key substituted (the bastion's restored).
    write_pins(&wrong(), &jump_key);
    let (j, f) = (jump_host.log_mark(), final_host.log_mark());
    let (ok, stdout, stderr, _) = connect("hm-u5a-b");
    assert!(!ok && !stdout.contains("hm-u5a-b"));
    assert!(stderr.contains("Host key verification failed"), "{stderr}");
    assert_eq!(
        accepted(&jump_host, j),
        1,
        "the bastion authenticated and forwarded"
    );
    assert_eq!(
        attempts(&final_host, f),
        0,
        "no publickey attempt at the substituted final host"
    );
    assert!(!stderr.contains("Authenticated to"), "{stderr}");

    // C. a user KnownHostsCommand serving a wrong key, after P's block: never consulted.
    write_pins(&final_key, &jump_key);
    let marker = dir.join("khc-ran");
    let script = dir.join("khc");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ntouch '{}'\nprintf '%s\\n' \"$1 {}\"\n",
            marker.display(),
            wrong()
        ),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::write(
        &config,
        format!(
            "{p}\nHost *\n    KnownHostsCommand {} %H\n",
            script.display()
        ),
    )
    .unwrap();
    let (ok, stdout, stderr, _) = connect("hm-u5a-c");
    assert!(ok && stdout.contains("hm-u5a-c"), "{stderr}");
    assert!(
        !marker.exists(),
        "the user's KnownHostsCommand was never run"
    );
    drop(agent);
}
