//! `container add|remove|mount-args` (M04 U5; ADR-0010 §4; revision 5 §17.1).
//!
//! * **`add <label>`** sends `environment.container_add`. The runtime answers with an
//!   `AddEnvironment` decision (the host check and the label rules come first, nothing written
//!   when they refuse). On an interactive terminal the session is attended first, the exact
//!   recorded decision is shown (the environment, its realization and the three disclosures:
//!   not a sandbox, engine access is host-root-equivalent, same-UID use), a typed `yes` is
//!   required and only then is `Decide approve` sent; the answer is the new environment's
//!   view. Otherwise nothing more is sent and the command exits 3 with `next.decision_ref`.
//! * **`remove <environment>`** (the environment ID, or its label) sends
//!   `environment.container_remove`: the owner role executes it, no decision. A second remove
//!   answers `OK` with nothing removed.
//! * **`mount-args <environment>`** is read-only: it finds the environment in
//!   `inspect environments` and prints the mount instruction (the same one the `ensure` result
//!   carries): with `--json`, the descriptor; otherwise engine-neutral lines.
//!
//! Heimdall never invokes or contacts a container engine.

use heimdall_contract::environment::{
    EnvironmentKindView, EnvironmentRequest, EnvironmentState, EnvironmentView, EnvironmentsView,
    RealizationDescriptor, RealizationView,
};
use heimdall_contract::ids::EnvironmentId;
use heimdall_contract::request::{InspectSubject, Request};
use heimdall_contract::{Code, ExitCode};

use crate::cli::{ContainerCommand, Prompter, Session, TerminalPrompt};
use crate::client::Ctx;
use crate::setup_cmd::{self, Outcome, failure};

/// The preface of the `AddEnvironment` confirmation.
const ADD_PREFACE: &str = "Add this local container environment (ADR-0010 §4). Heimdall will create the environment's stable directory; a container that mounts it read-only gets one binding's signing endpoint and public files, and nothing else. This is not a sandbox: any process of your user can use the endpoint, and anyone who can drive the container engine has host-root-equivalent power over your sockets.";

/// Handle `container` (module docs).
pub(crate) fn run(ctx: &Ctx, command: ContainerCommand) -> ExitCode {
    match command {
        ContainerCommand::Add { label } => setup_cmd::block(ctx, async { add(ctx, &label).await }),
        ContainerCommand::Remove { environment } => {
            setup_cmd::block(ctx, async { remove(ctx, &environment).await })
        }
        ContainerCommand::MountArgs { environment } => {
            setup_cmd::block(ctx, async { mount_args(ctx, &environment).await })
        }
    }
}

/// `container add <label>`.
async fn add(ctx: &Ctx, label: &str) -> Outcome {
    let mut client = match setup_cmd::session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    add_with(&mut client, &mut TerminalPrompt, ctx, label).await
}

/// [`add`] over any session and prompt (the flow's test seam).
async fn add_with<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    label: &str,
) -> Outcome {
    if let Err(refused) = setup_cmd::attend_first(s, ctx).await {
        return Outcome::of(refused);
    }
    let env = s
        .request(Request::Environment(EnvironmentRequest::ContainerAdd {
            label: label.to_owned(),
        }))
        .await;
    let Some(decision) = setup_cmd::pending_decision(&env) else {
        return Outcome::of(env);
    };
    if !ctx.interactive() {
        // The pending decision stays pending; nothing more is sent (exit 3).
        return Outcome::of(env);
    }
    let decided =
        setup_cmd::confirm_and_decide(s, p, ctx, &decision, ADD_PREFACE, None, None).await;
    if decided.code != Code::Ok {
        return Outcome::of(decided);
    }
    let human = decided
        .data
        .get("environment")
        .and_then(|v| serde_json::from_value::<EnvironmentView>(v.clone()).ok())
        .map(|v| view_text(&v))
        .unwrap_or_default();
    Outcome::of(decided).with_human(human)
}

/// `container remove <environment>`.
async fn remove(ctx: &Ctx, environment: &str) -> Outcome {
    let mut client = match setup_cmd::session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let id = match resolve(&mut client, environment).await {
        Ok(v) => v.environment_id,
        Err(o) => return o,
    };
    let env = client
        .request(Request::Environment(EnvironmentRequest::ContainerRemove {
            environment_id: id,
        }))
        .await;
    let human = env
        .data
        .get("environment")
        .and_then(|v| serde_json::from_value::<EnvironmentView>(v.clone()).ok())
        .map(|v| view_text(&v))
        .unwrap_or_default();
    Outcome::of(env).with_human(human)
}

/// `container mount-args <environment>`.
async fn mount_args(ctx: &Ctx, environment: &str) -> Outcome {
    let mut client = match setup_cmd::session(ctx, false).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let view = match resolve(&mut client, environment).await {
        Ok(v) => v,
        Err(o) => return o,
    };
    let RealizationView::Container { directory, .. } = &view.realization else {
        return setup_cmd::usage("that environment is not a container environment");
    };
    if view.state != EnvironmentState::Active {
        return Outcome::of(failure(
            Code::NotFound,
            "the container environment was removed",
            Some(heimdall_contract::envelope::reason::ENVIRONMENT_REMOVED),
        ));
    }
    let descriptor = heimdall_app::operations::container_m04::realization_descriptor(directory);
    let mut env = heimdall_contract::envelope::Envelope::ok(serde_json::json!({
        "environment": view,
        "realization": descriptor,
    }));
    env.code = Code::Ok;
    let human = mount_args_text(&descriptor);
    Outcome::of(env).with_human(human)
}

/// The container environment named by `environment` (an environment ID, or a label), from
/// `inspect environments`. A label names one container environment in the set.
async fn resolve<S: Session>(s: &mut S, environment: &str) -> Result<EnvironmentView, Outcome> {
    let data = setup_cmd::inspect(s, InspectSubject::Environments).await?;
    let items = data
        .get("items")
        .cloned()
        .map(|items| serde_json::json!({ "items": items }))
        .and_then(|v| serde_json::from_value::<EnvironmentsView>(v).ok())
        .ok_or_else(|| {
            Outcome::of(failure(
                Code::CapabilityUnavailable,
                "the runtime did not list its environments (an owner session is needed)",
                None,
            ))
        })?;
    let by_id = EnvironmentId::parse(environment).ok();
    let mut found: Vec<EnvironmentView> = items
        .items
        .into_iter()
        .filter(|v| v.kind == EnvironmentKindView::Container)
        .filter(|v| match &by_id {
            Some(id) => v.environment_id == *id,
            None => v.label.as_deref() == Some(environment),
        })
        .collect();
    // A label names the container environment in the set; a removed one only by its ID.
    if by_id.is_none() {
        found.retain(|v| v.state == EnvironmentState::Active);
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(Outcome::of(failure(
            Code::NotFound,
            "no container environment has that ID or label",
            None,
        ))),
        _ => Err(setup_cmd::usage(
            "several container environments match; use the environment ID",
        )),
    }
}

/// One environment as a line of text.
fn view_text(v: &EnvironmentView) -> String {
    let label = v.label.as_deref().unwrap_or("-");
    format!(
        "container environment {} (label {label}, {:?})",
        v.environment_id, v.state
    )
}

/// Single-quote `text` for a POSIX shell when it needs it.
fn shell_quote(text: &str) -> String {
    if !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-:=,@+".contains(&b))
    {
        text.to_owned()
    } else {
        format!("'{}'", text.replace('\'', "'\\''"))
    }
}

/// The engine-neutral mount arguments (module docs), one per line, then the user-namespace
/// notes (ADR-0010 §4 item 5).
fn mount_args_text(d: &RealizationDescriptor) -> String {
    let mut lines = Vec::new();
    if let Some(m) = &d.mount {
        lines.push(format!(
            "--mount type=bind,source={},target={}{}",
            shell_quote(&m.source),
            m.target,
            if m.read_only { ",readonly" } else { "" }
        ));
    }
    for (name, value) in &d.environment {
        lines.push(format!("--env {}", shell_quote(&format!("{name}={value}"))));
    }
    lines.push(String::new());
    lines.push("# The endpoint admits only your own uid, as the host sees it:".to_owned());
    lines.push(
        "#   rootless Podman: add --userns=keep-id; rootless Docker: container root maps to you"
            .to_owned(),
    );
    lines.push(
        "#   rootful engine: add --user <your uid>:<your gid> (root and unmapped sub-uids are refused)"
            .to_owned(),
    );
    lines.push(
        "# Not a sandbox: any process of your user can use the endpoint, and engine access is host-root-equivalent."
            .to_owned(),
    );
    lines.join("\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use heimdall_app::operations::container_m04::realization_descriptor;

    /// `mount-args` prints the instruction of the `ensure` result: a read-only bind of the
    /// directory, `SSH_AUTH_SOCK`, and the user-namespace notes; a path with a space is quoted.
    #[test]
    fn mount_args_print_the_read_only_bind_and_the_uid_notes() {
        let text = mount_args_text(&realization_descriptor(
            "/run/user/1000/hm dir/c/0123456789abcdef",
        ));
        assert!(
            text.contains(
                "--mount type=bind,source='/run/user/1000/hm dir/c/0123456789abcdef',target=/run/heimdall,readonly"
            ),
            "{text}"
        );
        assert!(text.contains("--env SSH_AUTH_SOCK=/run/heimdall/agent.sock"));
        assert!(text.contains("--env 'GIT_SSH_COMMAND=ssh -F /run/heimdall/ssh_config'"));
        assert!(text.contains("--userns=keep-id") && text.contains("--user <your uid>"));
    }
}
