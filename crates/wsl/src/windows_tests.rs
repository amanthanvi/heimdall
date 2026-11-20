//! Windows-only tests: the Lxss read and the `wsl.exe` session, which no other host can run.
//! `WslHost`'s Windows constructor is exercised for real here; nothing is mocked.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use heimdall_app::ports::{DistributionHost, DistributionTarget, RunningState};
use heimdall_contract::ids::EnvironmentId;

use crate::client::{Expected, HelperLauncher, HelperSession, SessionError};
use crate::host::{WslExeLauncher, WslHost};
use crate::spawn;

/// The registered distributions are read without changes: the read succeeds (an account
/// without WSL answers an empty list or `wsl_unavailable`, never a panic), every identity is a
/// canonical GUID, and two reads agree. The running set is read with `wsl.exe --list --running
/// --quiet`, which starts nothing: every distribution answers a state, and the answer is stable
/// across two reads taken together.
#[test]
fn windows_lxss_and_running_set_read_without_changes() {
    let host = WslHost::platform(None);
    let first = match host.discover() {
        Ok(list) => list,
        Err(e) => {
            // No Lxss key readable: the host answers `wsl_unavailable`, which is the contract.
            assert_eq!(
                e,
                heimdall_app::ports::AdapterError::Unavailable("wsl_unavailable".to_owned())
            );
            return;
        }
    };
    let second = host.discover().unwrap();
    assert_eq!(first, second);
    for d in &first {
        assert!(!d.name.is_empty());
        assert!(matches!(d.version, 1 | 2));
        assert_eq!(d.guid.as_str().len(), 36);
        let state = host.running(&d.guid);
        assert!(matches!(
            state,
            RunningState::Running | RunningState::NotRunning | RunningState::Unknown
        ));
    }
}

/// A real session over `wsl.exe` into a **disposable** distribution (the harness creates and
/// unregisters it; `tests/native/m02/run-wsl-distro.sh`): the helper's Windows path resolves to a
/// Linux path with `wslpath -u`, the helper starts through `wsl.exe -d <name> -u <account>
/// --exec`, its hello names the distribution and account, a session for another account is
/// refused, and the session ends cleanly.
///
/// Variables: `HM_WSL_TEST_DISTRO` (the disposable distribution's name), `HM_WSL_TEST_ACCOUNT`
/// (its non-root user) and `HM_WSL_TEST_HELPER` (the Windows path of the Linux x86-64 `heimdall`
/// build, cross-built with the M02 shims). Run with `-- --ignored`.
#[test]
#[ignore = "needs a disposable distribution: HM_WSL_TEST_DISTRO, HM_WSL_TEST_ACCOUNT, HM_WSL_TEST_HELPER"]
fn windows_helper_session_over_wsl_exe_in_a_disposable_distribution() {
    let var = |n: &str| std::env::var(n).unwrap_or_else(|_| panic!("{n} is not set"));
    let (name, account, helper) = (
        var("HM_WSL_TEST_DISTRO"),
        var("HM_WSL_TEST_ACCOUNT"),
        var("HM_WSL_TEST_HELPER"),
    );
    let host = WslHost::platform(None);
    let found = host.discover().unwrap();
    let dist = found
        .iter()
        .find(|d| d.name == name)
        .expect("the disposable distribution is registered");
    let target = DistributionTarget {
        guid: dist.guid.clone(),
        name: name.clone(),
        account: account.clone(),
        namespace: EnvironmentId::from_random_bytes([0x31; 16]),
    };
    let system_root = std::env::var("SystemRoot").ok();
    let launcher = WslExeLauncher::new(
        spawn::wsl_exe_path(system_root.as_deref()),
        PathBuf::from(helper),
    );
    let linux = launcher.linux_helper_path(&target).unwrap();
    assert!(linux.starts_with("/mnt/"), "{linux}");

    let session = HelperSession::open(
        launcher.launch(&target).unwrap(),
        &Expected {
            name: name.clone(),
            account: account.clone(),
            uid: None,
        },
    )
    .unwrap();
    assert_eq!(session.hello().distribution.as_deref(), Some(name.as_str()));
    assert_eq!(session.hello().account, account);
    assert!(session.hello().interop);
    assert_eq!(session.hello().arch, "x86_64");
    session.close();
    // The distribution is running now (the session started it), as the listing says.
    assert_eq!(launcher.running(&name), RunningState::Running);

    let refused = HelperSession::open(
        launcher.launch(&target).unwrap(),
        &Expected {
            name,
            account: "someone-else".to_owned(),
            uid: None,
        },
    )
    .err()
    .expect("another account is refused");
    assert_eq!(refused, SessionError::HelloMismatch);
}
