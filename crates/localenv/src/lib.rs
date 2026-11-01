//! The local environment (m02-plan U3, U4; ADR-0007 §5, §6, §9).
//!
//! * U3: [`paths`], [`fs`], [`clients`], [`agents`], [`known_hosts`], [`local_query`],
//!   [`git`], [`doctor`], [`probe`] and the platform calls in [`sys`];
//! * U4: [`projection`] (the file transaction behind the `ProjectionWriter` port, the
//!   `ResourceCleaner` for projection resources) and [`materialize`];
//! * integrator: [`env`] (the environment snapshot and platform tag shared with the
//!   process contract).
//!
//! Discovery and the default doctor are passive: they run no configuration command,
//! contact no agent, provider or network, and change nothing. Explicit probes are
//! labelled levels recorded in a `ProbeRecord` (ADR-0007 §6).
//!
//! **Skeleton status (m02-plan U0, wave 0).** Every frozen type and signature exists
//! here (the replacement primitive and quarantine, the materializer, the recovery
//! function's results); the inputs that cross the `ProjectionWriter` port live in
//! `heimdall_domain::projection` (wave-0 verifier E8). Unit bodies are
//! `todo!("M02-U3 …")`/`todo!("M02-U4 …")`. None is reachable in this build: the
//! runtime is given no `ProjectionWriter` (`OperationsConfig.projection` is `None`),
//! no cleaner of this crate is registered, and the CLI's M02 handlers answer "not
//! available in this build" without calling this crate (m02-plan "Skeleton rule").
//! [`env`], [`paths::SshPaths::with_test_override`] and `projection::git::lock_holder`
//! are complete.
//!
//! **`unsafe`:** only [`sys`] may contain it (overview §9 item 3).

pub mod agents;
pub mod clients;
pub mod doctor;
pub mod env;
pub mod fs;
pub mod git;
pub mod known_hosts;
pub mod local_query;
pub mod materialize;
pub mod paths;
pub mod probe;
pub mod projection;
pub mod sys;

#[cfg(test)]
mod tests {
    use heimdall_domain::projection::is_lock_holder_line;

    use super::paths::SshPaths;
    use super::projection::git::lock_holder;

    #[test]
    fn lock_holder_renders_the_domain_line_for_its_generation() {
        let k = lock_holder(7, [0xab; 16]);
        assert_eq!(
            k.bytes(),
            format!("heimdall setup lock, generation 7, {}\n", "ab".repeat(16)).as_bytes()
        );
        assert!(is_lock_holder_line(k.bytes(), 7));
        assert!(!is_lock_holder_line(k.bytes(), 8));
        assert!(k.bytes().len() <= heimdall_domain::projection::bounds::LOCK_HOLDER_MAX);
    }

    #[test]
    fn test_override_paths_stay_under_the_scratch_home() {
        let home = std::path::PathBuf::from("/scratch/home");
        let sys = std::path::PathBuf::from("/scratch/etc-ssh");
        let p = SshPaths::with_test_override(home.clone(), sys.clone());
        assert_eq!(p.account_home, home);
        assert_eq!(p.user_dir, home.join(".ssh"));
        assert_eq!(p.user_config, home.join(".ssh").join("config"));
        assert_eq!(p.system_dir, sys);
        assert_eq!(p.system_config, sys.join("ssh_config"));
    }
}
