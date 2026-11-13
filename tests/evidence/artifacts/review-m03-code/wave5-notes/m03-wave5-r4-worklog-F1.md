# F1 worklog (M03 wave 5 r4): intermittent Windows digest mismatch in `git_first_adoption_previews_reproduce_their_plan_digest`

## Goal
Prove/disprove: a timed-out `git` local query (LOCAL_QUERY_TIMEOUT 2 s) makes an observation
incomplete -> Git item `not_applicable` (`git_config_unreadable`) -> different plan digest.
If confirmed: 10 s bound, injectable for tests, diagnosable test, regression
`git_preview_digest_is_stable_under_a_slow_git` with revert proof.

## Facts read
- Users of LOCAL_QUERY_TIMEOUT: local_query.rs (run_version, unit test), git.rs git_query
  (observe: `git var GIT_CONFIG_SYSTEM`, `git config --system|--global ... --get-all core.sshCommand`;
  winning_origin; resolve_run_selection), known_hosts.rs keygen_lookup, projection/git.rs parse_check.
- plan.rs plan_git_apply: `!obs.unreadable.is_empty()` -> not_applicable(GIT_CONFIG_UNREADABLE).
- Docs stating 2 s for local queries: ADR-0007 l.666, l.2097; m02-plan l.811; doctor.rs l.16;
  local_query.rs l.2; git.rs l.12; projection/git.rs l.148.

## Progress (all done)
- CONFIRMED on macOS (temporary test, removed): wrapper git sleeping 3 s on the 2nd `--global`
  query, bound 2 s: a=ab7ec777… (Applicable) b=55760601… (NotApplicable, git_config_unreadable);
  third fast preview c=ab7ec777… again. Second preview took 2.06 s.
- Fix: LOCAL_QUERY_TIMEOUT 10 s; git.rs QueryAnswer::Failed{timed_out}, entries name the query
  and the bound (`git config --global (timed out after 2000 ms)`, `git system configuration (path
  not established): git var GIT_CONFIG_SYSTEM (timed out …)`); observe_global[_for]_within(bound);
  ProjectionTestConfig.local_query_timeout; ProjectionConfig.git_observed (test diagnostics).
- Test: Fx::complete_preview names incomplete observations; regression
  git_preview_digest_is_stable_under_a_slow_git (#[cfg(unix)]).
- Revert proof: constant -> 2 s: exit 101 ("slow (3 s), at LOCAL_QUERY_TIMEOUT: ... incomplete:
  Some([\"git config --global (timed out after 2000 ms)\"])"); restored, shasum OK
  (7b4009b3…), whole target 44 passed exit 0 (umask 002).
- Checks: clippy host 0; clippy-windows 0; linux-xcheck -p heimdall-localenv 0; localenv lib 89 ok;
  git_observe 17 ok; projection 112 ok; e2e_cli_m03 enroll_ctrl_c_between_step_and_result ok.
  integration_doctor: umask 002 -> 4 fail (pre-existing ssh perms), umask 077 -> 24 ok.
