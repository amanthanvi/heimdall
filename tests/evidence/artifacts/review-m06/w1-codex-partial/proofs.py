import os
from pathlib import Path
import subprocess

base = Path(__file__).parent
src = base / "source"
env = os.environ.copy()
env["CARGO_HOME"] = env.get("CARGO_HOME", str(Path.home() / ".cargo"))
env["RUSTUP_HOME"] = env.get("RUSTUP_HOME", str(Path.home() / ".rustup"))
env.update(
    HOME=str(base / "home"),
    HEIMDALL_HOME=str(base / "heimdall-home"),
    HEIMDALL_TEST_SSH_HOME=str(base / "ssh-home"),
    TMPDIR=str(base / "tmp"),
    CARGO_BUILD_JOBS="4",
)
env.pop("SSH_AUTH_SOCK", None)
env.pop("CARGO_TARGET_DIR", None)

paired = ["-p", "heimdall-app", "--test", "integration_paired_scope_m06"]
remote = ["-p", "heimdall-remote", "--test", "model_remote_roles"]
verifier = ["-p", "heimdall-remote", "--lib", "each_failing_field_is_refused_by_name"]
operations = "crates/app/src/operations.rs"
events = "crates/app/src/events.rs"
policy = "crates/remote/src/sshd_policy.rs"

def run(label, args):
    with (base / (label + ".log")).open("w") as log:
        cp = subprocess.run(["cargo", "test", "--locked", "--offline", *args],
                            cwd=src, env=env, stdout=log, stderr=subprocess.STDOUT)
    lines = (base / (label + ".log")).read_text().splitlines()
    result = [l for l in lines if l.startswith("test result:")]
    panic = [l.split(" panicked at ", 1)[-1].split(":\n")[0] for l in lines
             if " panicked at crates/" in l or " panicked at ../../tests/" in l]
    print(label, cp.returncode, *result, *panic, flush=True)

def replace_only(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new, 1)

def proof(label, file, old, new, args):
    path = src / file
    original = path.read_text()
    path.write_text(replace_only(original, old, new))
    try:
        run(label, args)
    finally:
        path.write_text(original)

proof("revert-observe", events, "    caller.may_access(owner)",
      "    owner.same_caller(caller) || caller.is_owner()", paired)
proof("revert-cancel", operations,
      "let Some(mut op) = tx\n                    .operation(&id)?\n                    .filter(|o| visible_to(&o.key.caller, &ctx))",
      "let Some(mut op) = tx.operation(&id)?", paired)
proof("revert-binding", "crates/domain/src/binding.rs", "    caller.may_access(&binding.owner)",
      "    binding.owner.same_caller(caller) || caller.is_owner()", paired)
proof("revert-page", operations, "if crate::events::event_visible_in(tx, &s.event, &ctx)? {", "{", paired)
proof("revert-resume", events, "if event_visible_in(tx, &stored.event, &reader)? {", "{", paired)
proof("revert-snapshot-open", events, "if managed.contains(&op.environment) && visible_to(&op.key.caller, reader) {",
      "if managed.contains(&op.environment) {", paired)
proof("revert-snapshot-named", events, "            .filter(|op| visible_to(&op.key.caller, reader))\n",
      "", paired)
run("restore-paired", paired)
proof("revert-elapsed", "crates/remote/src/invitations.rs", "if other_boot || elapsed_passed || wall_passed {",
      "if other_boot || wall_passed {", remote + ["focused_fault_wall_clock_rollback_between_authentication_and_join"])
proof("revert-identity", "crates/remote/src/invitations.rs",
      "            && line_fingerprint == Some(&inv.key_fingerprint)\n",
      "", remote + ["retried_join_checks_identity_before_the_recorded_result"])
proof("revert-forcecommand", policy,
      '    require(\n        &pairs,\n        "forcecommand",\n        PolicyField::ForceCommand,\n        "none",\n        "a ForceCommand applies to the account",\n    )?;\n',
      "", verifier)
run("restore-remote", remote)
run("restore-verifier", verifier)
