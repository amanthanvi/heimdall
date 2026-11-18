//! `export [--redact] [--out FILE]` and `import BUNDLE [--yes]` (M05 U7, U9a; ADR-0011 §2.4
//! I4; ADR-0006 §17.9 items 15–17; m05-plan U7, U9).
//!
//! **Export** is a read (`inspect export`, `redact` on the request; it never starts the
//! runtime): the bundle carries portable intent only (catalog destinations, identity
//! references, profiles) and the list of what must be re-established, never a policy,
//! workspace record, permission, grant, decision, enrollment, path or private material.
//! The CLI checks that its bytes pass the importer's own parser before it prints or writes
//! them. Without `--out` the bundle is printed on stdout (`--json`: in the envelope); with
//! `--out` it is written to a new file, created exclusively and owner-only, never
//! replacing one.
//!
//! **Import** reads one bounded regular file and parses it with the importer's parser
//! (`heimdall_app::operations::parse_import_bundle`: an unknown or authority-bearing key at
//! any depth refuses the whole bundle, `USAGE_ERROR`, before anything is sent). It then
//! sends `catalog apply_import` with **`dry_run`** (a read: nothing is written), shows the
//! plan — what would be added, what is unchanged, every conflict, the identity references
//! that need a local key, the exported host-key fingerprints for comparison only, and the
//! `reestablish` list — and asks on a terminal for a typed `yes` (`--yes` without one).
//! Only then is the same bundle imported under the same request ID. An import grants no
//! access and trusts no host key (I4); it is not an owner decision, so nothing is
//! attended. Under `--non-interactive` (or without a terminal) and without `--yes`,
//! nothing is imported (exit 3).

use std::io::Read as _;
use std::path::Path;

use heimdall_contract::catalog::CatalogRequest;
use heimdall_contract::envelope::{EffectStatus, Envelope};
use heimdall_contract::project::PortableBundle;
use heimdall_contract::request::{InspectRequest, InspectSubject, Request};
use heimdall_contract::{Code, ExitCode};

use crate::cli::{ExportArgs, ImportArgs, Prompter, Session, TerminalPrompt};
use crate::client::Ctx;
use crate::output;
use crate::prompt::Answer;
use crate::setup_cmd::{Outcome, block, failure, non_interactive_reason, request_id, usage};

/// The largest bundle file read (`heimdall_project`'s bound, plus one byte to detect more).
const MAX_BUNDLE_FILE_BYTES: u64 = 1 << 20;

/// Handle `export`.
pub(crate) fn export(ctx: &Ctx, a: &ExportArgs) -> ExitCode {
    let ctx2 = ctx.clone();
    match crate::service_cmd::current_thread() {
        Ok(rt) => {
            let r = rt.block_on(export_flow(&ctx2, a));
            match r {
                Ok(Exported::Stdout(text)) if !ctx.json => {
                    use std::io::Write as _;
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(text.as_bytes());
                    let _ = out.flush();
                    ExitCode::Success
                }
                Ok(Exported::Stdout(text)) => {
                    let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                    Outcome::of(Envelope::ok(value)).emit(ctx)
                }
                Ok(Exported::File(o)) => o.emit(ctx),
                Err(o) => o.emit(ctx),
            }
        }
        Err(env) => Outcome::of(output::error_value(env)).emit(ctx),
    }
}

enum Exported {
    /// The bundle text for stdout.
    Stdout(String),
    /// Written to a file: the summary.
    File(Box<Outcome>),
}

async fn export_flow(ctx: &Ctx, a: &ExportArgs) -> Result<Exported, Outcome> {
    let mut s = crate::m05_cmd::session(ctx, false).await?;
    let env = s
        .request(Request::Inspect(InspectRequest {
            subject: InspectSubject::Export,
            preview: None,
            cwd: None,
            redact: a.redact,
        }))
        .await;
    if !env.code.is_success() {
        return Err(Outcome::of(env));
    }
    let bundle: PortableBundle = serde_json::from_value(env.data).map_err(|_| {
        Outcome::of(failure(
            Code::InternalError,
            "the runtime's bundle cannot be read",
            None,
        ))
    })?;
    let mut text = serde_json::to_string_pretty(&bundle).map_err(|_| {
        Outcome::of(failure(
            Code::InternalError,
            "the bundle cannot be rendered",
            None,
        ))
    })?;
    text.push('\n');
    // What is written must be what an import accepts.
    if heimdall_app::operations::parse_import_bundle(text.as_bytes()).is_err() {
        return Err(Outcome::of(failure(
            Code::InternalError,
            "the exported bundle does not pass the importer's checks; nothing was written",
            None,
        )));
    }
    let Some(out) = &a.out else {
        return Ok(Exported::Stdout(text));
    };
    write_new(out, text.as_bytes())?;
    let data = serde_json::json!({
        "written": out.display().to_string(),
        "redacted": a.redact,
        "destinations": bundle.destinations.len(),
        "identities": bundle.identities.len(),
        "profiles": bundle.profiles.len(),
    });
    let human = format!(
        "Wrote {} destination(s), {} identity reference(s) and {} profile(s){}.\nThe bundle carries intent only: no policy, trust record, grant or private material. Re-establish on the other installation:\n{}",
        bundle.destinations.len(),
        bundle.identities.len(),
        bundle.profiles.len(),
        if a.redact { ", redacted" } else { "" },
        bundle
            .reestablish
            .iter()
            .map(|r| format!("  - {r}\n"))
            .collect::<String>()
    );
    Ok(Exported::File(Box::new(
        Outcome::of(Envelope::ok(data)).with_human(human),
    )))
}

/// Create `path` exclusively and owner-only, and write `bytes` (never replacing a file).
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Outcome> {
    use std::io::Write as _;
    let mut f = heimdall_localenv::sys::create_owner_only_exclusive(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            usage("--out names an existing file; the bundle never replaces one")
        } else {
            usage(&format!("--out cannot be created: {}", e.kind()))
        }
    })?;
    f.write_all(bytes).and_then(|()| f.sync_all()).map_err(|e| {
        Outcome::of(failure(
            Code::InternalError,
            &format!("the bundle could not be written: {}", e.kind()),
            None,
        ))
    })
}

/// Read a bundle file: a regular file of at most [`MAX_BUNDLE_FILE_BYTES`].
fn read_bundle(path: &Path) -> Result<Vec<u8>, Outcome> {
    let f = std::fs::File::open(path)
        .map_err(|e| usage(&format!("the bundle cannot be read: {}", e.kind())))?;
    let meta = f
        .metadata()
        .map_err(|e| usage(&format!("the bundle cannot be read: {}", e.kind())))?;
    if !meta.is_file() {
        return Err(usage("the bundle is not a regular file"));
    }
    let mut bytes = Vec::new();
    f.take(MAX_BUNDLE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| usage(&format!("the bundle cannot be read: {}", e.kind())))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BUNDLE_FILE_BYTES {
        return Err(usage("the bundle exceeds the size bound"));
    }
    Ok(bytes)
}

/// The human form of an import plan (dry run or applied).
pub(crate) fn render_plan(v: &serde_json::Value) -> String {
    let n = |k: &str| {
        v.get(
            if v.get("dry_run").and_then(serde_json::Value::as_bool) == Some(true) {
                "would_apply"
            } else {
                "applied"
            },
        )
        .and_then(|c| c.get(k))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
    };
    let dry = v.get("dry_run").and_then(serde_json::Value::as_bool) == Some(true);
    let mut out = if dry {
        "Import plan (a dry run: nothing has been written):\n".to_owned()
    } else {
        "Imported:\n".to_owned()
    };
    out.push_str(&format!(
        "  {}: {}, unchanged: {}, conflicts (never applied): {}, need a local key: {}\n",
        if dry { "would add" } else { "added" },
        n("added"),
        n("unchanged"),
        n("conflicts"),
        n("needs_local"),
    ));
    let entries = v
        .get("plan")
        .and_then(|p| p.as_array())
        .map_or(&[][..], Vec::as_slice);
    let field = |e: &serde_json::Value, k: &str| {
        e.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .to_owned()
    };
    for e in entries {
        let mut line = format!(
            "  {} {}: {}",
            field(e, "kind"),
            field(e, "id"),
            field(e, "status")
        );
        if let Some(r) = e.get("reason").and_then(|r| r.as_str()) {
            line.push_str(&format!(" ({r})"));
        }
        out.push_str(&line);
        out.push('\n');
    }
    let fingerprints: Vec<String> = entries
        .iter()
        .flat_map(|e| {
            let id = field(e, "id");
            e.get("host_key_fingerprints")
                .and_then(|f| f.as_array())
                .map(|f| {
                    f.iter()
                        .filter_map(|x| x.as_str())
                        .map(|x| format!("  {id}: {x}\n"))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect();
    if !fingerprints.is_empty() {
        out.push_str("Host-key fingerprints the exporting installation knew (for your comparison only; an import never trusts a host key):\n");
        out.push_str(&fingerprints.concat());
    }
    let reestablish: Vec<&str> = v
        .get("reestablish")
        .and_then(|r| r.as_array())
        .map(|r| r.iter().filter_map(|x| x.as_str()).collect())
        .unwrap_or_default();
    if !reestablish.is_empty() {
        out.push_str("Re-establish locally (an import never carries these):\n");
        for r in reestablish {
            out.push_str(&format!("  - {r}\n"));
        }
    }
    out
}

/// Handle `import`.
pub(crate) fn import(ctx: &Ctx, a: &ImportArgs) -> ExitCode {
    block(ctx, async move {
        let bytes = match read_bundle(&a.bundle) {
            Ok(b) => b,
            Err(o) => return o,
        };
        let bundle = match heimdall_app::operations::parse_import_bundle(&bytes) {
            Ok(b) => b,
            Err(e) => return Outcome::of(output::error_value(e.into_envelope())),
        };
        let request_id = match request_id(a.request_id.as_deref()) {
            Ok(r) => r,
            Err(o) => return o,
        };
        let mut s = match crate::m05_cmd::session(ctx, true).await {
            Ok(s) => s,
            Err(o) => return o,
        };
        import_flow(&mut s, &mut TerminalPrompt, ctx, bundle, request_id, a.yes).await
    })
}

/// The import on a connected session (module docs): the dry run, the plan, the
/// confirmation, then the import.
pub(crate) async fn import_flow<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    bundle: PortableBundle,
    request_id: heimdall_contract::ids::RequestId,
    yes: bool,
) -> Outcome {
    let request = |dry_run: bool| {
        Request::Catalog(CatalogRequest::ApplyImport {
            bundle: bundle.clone(),
            dry_run,
            request_id: request_id.clone(),
        })
    };
    let dry = s.request(request(true)).await;
    if !dry.code.is_success() {
        return Outcome::of(dry);
    }
    let plan = render_plan(&dry.data);
    let would_add = dry
        .data
        .get("would_apply")
        .and_then(|c| c.get("added"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if would_add == 0 {
        let human = format!(
            "{plan}Nothing to import: the catalog already has everything this bundle can add.\n"
        );
        return Outcome::of(dry).with_human(human);
    }
    if !yes {
        if !ctx.interactive() {
            output::diagnostic(&plan);
            let e = heimdall_app::OpError::new(
                Code::InteractionRequired,
                format!(
                    "not confirmed ({}): nothing was imported; review the plan and import with --yes",
                    non_interactive_reason(ctx)
                ),
            )
            .with_effect(EffectStatus::None);
            return Outcome::of(output::error_value(e.into_envelope()));
        }
        let text = format!(
            "{plan}Importing adds catalog intent only: no access is granted and no host key is trusted.\nImport exactly this plan?\n"
        );
        let answer = p.ask(&text).await;
        if answer != Answer::Yes {
            let e = heimdall_app::OpError::new(
                Code::InteractionRequired,
                format!("not confirmed ({}): nothing was imported", answer.reason()),
            )
            .with_effect(EffectStatus::None);
            return Outcome::of(output::error_value(e.into_envelope()));
        }
    }
    let applied = s.request(request(false)).await;
    let human = if applied.code.is_success() {
        render_plan(&applied.data)
    } else {
        String::new()
    };
    Outcome::of(applied).with_human(human)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorder {
        sent: Vec<bool>,
        dry: serde_json::Value,
    }

    impl Session for Recorder {
        async fn request(&mut self, request: Request) -> Envelope<serde_json::Value> {
            let Request::Catalog(CatalogRequest::ApplyImport { dry_run, .. }) = request else {
                panic!("only the import is sent");
            };
            self.sent.push(dry_run);
            if dry_run {
                Envelope::ok(self.dry.clone())
            } else {
                Envelope::ok(
                    serde_json::json!({"applied": {"added": 1}, "plan": [], "reestablish": []}),
                )
            }
        }
        async fn attend(&mut self) -> Envelope<serde_json::Value> {
            panic!("an import is not an owner decision: nothing attends");
        }
    }

    struct Script(Vec<Answer>, Vec<String>);

    impl Prompter for Script {
        async fn ask(&mut self, text: &str) -> Answer {
            self.1.push(text.to_owned());
            self.0.remove(0)
        }
    }

    fn plan(added: u64) -> serde_json::Value {
        serde_json::json!({
            "dry_run": true,
            "would_apply": {"added": added, "unchanged": 1, "conflicts": 1, "needs_local": 1},
            "plan": [
                {"kind": "destination", "id": "lab1", "status": "add",
                 "host_key_fingerprints": ["SHA256:AAAA"]},
                {"kind": "destination", "id": "lab2", "status": "conflict", "reason": "alias_collision"},
                {"kind": "identity", "id": "SHA256:BBBB", "status": "needs_local"},
            ],
            "reestablish": ["standing policies and project trust"],
        })
    }

    fn bundle() -> PortableBundle {
        serde_json::from_value(serde_json::json!({"schema": "heimdall-portable/1",
            "created_at": "2026-11-18T09:00:00Z"}))
        .unwrap_or_else(|e| panic!("{e}"))
    }

    fn ctx(tty: bool) -> Ctx {
        Ctx {
            json: true,
            non_interactive: false,
            home: None,
            stdin_tty: tty,
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| unreachable!())
            .block_on(f)
    }

    fn rid() -> heimdall_contract::ids::RequestId {
        heimdall_contract::ids::RequestId::parse("r").unwrap_or_else(|_| unreachable!())
    }

    /// The dry run always comes first and its plan is shown with every conflict, the
    /// identities that need a local key, the host-key fingerprints for comparison and the
    /// re-establish list; the import is sent only after a typed `yes` (or `--yes`), never
    /// without a terminal, and never when nothing would be added.
    #[test]
    fn the_import_previews_then_asks_then_applies() {
        let mut s = Recorder {
            sent: Vec::new(),
            dry: plan(1),
        };
        let mut p = Script(vec![Answer::Yes], Vec::new());
        let o = block_on(import_flow(
            &mut s,
            &mut p,
            &ctx(true),
            bundle(),
            rid(),
            false,
        ));
        assert_eq!(s.sent, [true, false]);
        assert_eq!(o.env.code, Code::Ok);
        let shown = &p.1[0];
        for needle in [
            "would add: 1",
            "lab2: conflict (alias_collision)",
            "needs_local",
            "lab1: SHA256:AAAA",
            "never trusts a host key",
            "standing policies and project trust",
        ] {
            assert!(shown.contains(needle), "{needle}: {shown}");
        }
        for answer in [Answer::No, Answer::Eof, Answer::TimedOut] {
            let mut s = Recorder {
                sent: Vec::new(),
                dry: plan(1),
            };
            let mut p = Script(vec![answer], Vec::new());
            let o = block_on(import_flow(
                &mut s,
                &mut p,
                &ctx(true),
                bundle(),
                rid(),
                false,
            ));
            assert_eq!(s.sent, [true], "{answer:?}");
            assert_eq!(o.exit, ExitCode::InteractionRequired);
        }
        let mut s = Recorder {
            sent: Vec::new(),
            dry: plan(1),
        };
        let mut p = Script(Vec::new(), Vec::new());
        let o = block_on(import_flow(
            &mut s,
            &mut p,
            &ctx(false),
            bundle(),
            rid(),
            false,
        ));
        assert_eq!(
            (s.sent.as_slice(), o.exit),
            (&[true][..], ExitCode::InteractionRequired)
        );
        let o = block_on(import_flow(
            &mut s,
            &mut p,
            &ctx(false),
            bundle(),
            rid(),
            true,
        ));
        assert_eq!(o.env.code, Code::Ok);
        assert_eq!(
            s.sent,
            [true, true, false],
            "--yes applies without a prompt"
        );
        let mut s = Recorder {
            sent: Vec::new(),
            dry: plan(0),
        };
        let o = block_on(import_flow(
            &mut s,
            &mut p,
            &ctx(true),
            bundle(),
            rid(),
            true,
        ));
        assert_eq!((s.sent.as_slice(), o.env.code), (&[true][..], Code::Ok));
        assert!(p.1.is_empty());
    }
}
