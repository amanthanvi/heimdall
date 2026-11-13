//! `heimdall connections [--json]` and `heimdall connections close <id>` (m03-plan
//! §5 items 4, 4a and 24; ADR-0008 D8).
//!
//! * `connections` lists the owned connections (`inspect connections`, a read: it
//!   never starts the runtime). An owned connection is a verified `ssh` client that
//!   `heimdall connect` or `heimdall run` launched; connections ordinary `ssh` opened
//!   are not Heimdall's and are not listed.
//! * `connections close <id>` sends `Connections::Close` (owner role only; narrowing,
//!   so no decision). The runtime re-verifies the process (PID, start time, image)
//!   before any signal; a process it cannot verify is **never signalled**, and this
//!   command says so. What the runtime answers is shown, never improved on.
//!
//! **Exit status** (ADR-0008 §17.25 item 16, Q-A1 (a)): the exit follows the envelope
//! code, as ADR-0006 §5 maps it. The runtime answers `OK` with `state` `closed`,
//! `closing` (the close is pending and retried) or `unverified`, and each exits 0. The
//! human text says plainly when nothing was closed (`unverified`: identity not verified,
//! nothing signalled; `closing`: still pending), and `--json` carries `state`.

use heimdall_contract::ExitCode;
use heimdall_contract::envelope::Envelope;
use heimdall_contract::ids::ConnectionId;
use heimdall_contract::managed::{ConnectionEntry, ConnectionsRequest, ConnectionsView};
use heimdall_contract::request::{InspectRequest, InspectSubject, Request};

use crate::cli::{ConnectionsArgs, ConnectionsCommand};
use crate::client::Ctx;
use crate::setup_cmd::{Outcome, block, session, usage};

/// Handle `connections`: no subcommand lists, `close <id>` closes.
pub(crate) fn run(ctx: &Ctx, args: ConnectionsArgs) -> ExitCode {
    match args.command {
        None => block(ctx, list(ctx)),
        Some(ConnectionsCommand::Close { id }) => block(ctx, close(ctx, id)),
    }
}

/// The footer every listing carries: what "owned" means (D8 item 2).
pub(crate) const OWNED_MEANING: &str = "Owned connections are the ssh clients `heimdall connect` and `heimdall run` started; connections ordinary ssh opened are not listed.";

/// The human listing of a `ConnectionsView`'s data: one block per connection, or that
/// there are none. A value that is not a view is shown as the runtime sent it.
#[must_use]
pub(crate) fn render_list(data: &serde_json::Value) -> String {
    let Ok(view) = serde_json::from_value::<ConnectionsView>(data.clone()) else {
        return serde_json::to_string_pretty(data).unwrap_or_default();
    };
    let mut out = String::new();
    if view.connections.is_empty() {
        out.push_str("No owned connections.\n");
    }
    for c in &view.connections {
        out.push_str(&entry_text(c));
    }
    out.push_str(OWNED_MEANING);
    out.push('\n');
    out
}

/// One connection: its identity, state, destination and grant, when it started, and
/// when Heimdall will close it (`closes_at`; none: it stays until its process ends).
fn entry_text(c: &ConnectionEntry) -> String {
    fn word<T: serde::Serialize>(v: &T) -> String {
        serde_json::to_value(v)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    }
    let closes = c.closes_at.map_or_else(
        || "when its process ends (existing connections stay)".to_owned(),
        |t| t.to_string(),
    );
    format!(
        "{} ({}, {})\n    destination {}, binding {}, grant {}\n    started {}, policy: existing {}, multiplexing {}\n    closes: {closes}\n",
        c.id,
        word(&c.kind),
        word(&c.state),
        c.destination_id,
        c.binding_id,
        c.grant_id,
        c.started_at,
        word(&c.policy.existing),
        word(&c.policy.multiplexing),
    )
}

/// `heimdall connections`: a read, never starting the runtime.
async fn list(ctx: &Ctx) -> Outcome {
    let mut client = match session(ctx, false).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let env = client
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Connections,
            preview: None,
        }))
        .await;
    let human = if env.code.is_success() {
        render_list(&env.data)
    } else {
        String::new()
    };
    Outcome::of(env).with_human(human)
}

/// `heimdall connections close <id>`.
async fn close(ctx: &Ctx, id: String) -> Outcome {
    let Ok(connection_id) = ConnectionId::parse(&id) else {
        return usage("invalid connection ID");
    };
    let mut client = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let env = client
        .request(Request::Connections(ConnectionsRequest::Close {
            connection_id,
        }))
        .await;
    close_outcome(env)
}

/// The outcome of a `Connections::Close` answer (module docs, "Exit status"): the
/// runtime's envelope and its exit, with a human sentence for its `state`.
#[must_use]
pub(crate) fn close_outcome(env: Envelope<serde_json::Value>) -> Outcome {
    if !env.code.is_success() {
        return Outcome::of(env);
    }
    let text = |k: &str| {
        env.data
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned()
    };
    let (id, kind, state) = (text("connection_id"), text("kind"), text("state"));
    let human = match state.as_str() {
        "closed" => format!("Closed owned connection {id} ({kind}).\n"),
        "unverified" => format!(
            "Connection {id} ({kind}) was not closed: its identity was not verified, so nothing was signalled. Heimdall treats it as unmanaged and leaves it running.\n"
        ),
        "closing" => format!(
            "Connection {id} ({kind}) is not closed yet: the close is still pending, and Heimdall retries until it ends. Run `heimdall connections` to see whether it is gone.\n"
        ),
        // A state this build does not know is not reported as closed.
        other => format!(
            "Connection {id} ({kind}): the runtime reports state {other:?}; it is not known to be closed.\n"
        ),
    };
    Outcome::of(env).with_human(human)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// ⟨§17.25 item 16⟩ A close the runtime answers `OK` exits 0 whatever its `state`,
    /// with the runtime's envelope unchanged; the human text says when nothing was closed.
    #[test]
    fn close_exit_follows_the_envelope_code() {
        for (state, says) in [
            ("closed", "Closed owned connection"),
            (
                "unverified",
                "was not closed: its identity was not verified, so nothing was signalled",
            ),
            ("closing", "is not closed yet: the close is still pending"),
            ("future_state", "it is not known to be closed"),
        ] {
            let env = Envelope::ok(serde_json::json!({
                "connection_id": "conn_x",
                "kind": "dedicated",
                "state": state,
            }));
            let out = close_outcome(env.clone());
            assert_eq!(out.exit, ExitCode::Success, "{state}");
            assert_eq!(out.env.data, env.data, "{state}");
            assert!(out.human.contains(says), "{state}: {}", out.human);
        }
    }
}
