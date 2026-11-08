//! `heimdall destination|identity|profile …` (m02-plan U9; ADR-0007 §7; §5 item 3).
//!
//! The read-only subcommands (`list`, `show`) are `inspect` requests that never start
//! the runtime. Every other subcommand is a `Request::Catalog` client that starts the
//! runtime on demand, with an idempotency request ID (given or fresh).
//!
//! * `identity adopt --pub FILE` reads one bounded `.pub` line (never a private key)
//!   and adopts it as a public-key-file identity.
//! * `identity adopt --from-agent` is the explicit `agent` probe (ADR-0007 §6): on an
//!   interactive TTY it asks first and names the provider and the endpoint; under
//!   `--non-interactive` it is refused unless `--active-probe agent` is given; a
//!   non-TTY stdin without `--non-interactive` cannot confirm (exit 3). It sends one
//!   identity-listing request to the session's agent and adopts the one identity the
//!   agent lists, or with `--fingerprint <fp>` the listed one with that fingerprint
//!   (ADR-0007 §12.30 item 12; several without it: refused, naming their fingerprints,
//!   so the owner chooses one with `--fingerprint` or adopts it with `--pub`; an
//!   unlisted fingerprint is `NOT_FOUND`). For each declared identity at that endpoint
//!   the listing lacks, it
//!   records the lapse (`WithdrawDeclaration { revision, reason: listing_missing }`)
//!   only when the runtime was already running; otherwise it reports `recorded: false`
//!   and the exact command (QR9).
//! * `identity declare-interaction <id> none` shows the decision text (ADR-0007 §7) and
//!   follows the confirmation contract (ADR-0006 §3.1): an attended `APPROVAL_REQUIRED`
//!   is confirmed with a typed `yes` before `Decide`; unattended, the runtime's
//!   `INTERACTION_REQUIRED` with `next.decision_ref` stands (exit 3).
//! * `identity withdraw-declaration <id>` sends `WithdrawDeclaration { reason: owner }`
//!   (narrowing; no decision).

use std::collections::BTreeSet;
use std::path::Path;

use heimdall_contract::catalog::{
    CatalogRequest, DeclaredInteraction, DestinationDefinitionSpec, DestinationSpec,
    IdentitySourceSpec, IdentitySpec, MAX_PUBLIC_KEY_BYTES, ProfileSpec, WithdrawReason,
};
use heimdall_contract::envelope::Envelope;
use heimdall_contract::ids::{AccountName, DestinationId, IdentityId, ProfileId};
use heimdall_contract::provider::{EndpointKind, EndpointRef};
use heimdall_contract::request::{AccessPairRef, InspectSubject, Request};
use heimdall_contract::{Code, ExitCode};

use crate::cli::{
    DestinationAddArgs, DestinationCommand, IdentityAdoptArgs, IdentityCommand, ProfileCommand,
    Prompter, Session, TerminalPrompt,
};
use crate::client::Ctx;
use crate::prompt::Answer;
use crate::setup_cmd::{
    Outcome, block, decided_request, failure, inspect, non_interactive_reason, not_confirmed,
    request_id, session, usage,
};

/// The decision text of `declare-interaction` (ADR-0007 §7).
pub(crate) const DECLARATION_TEXT: &str = "Heimdall will treat this key as needing no confirmation and will launch non-interactive work with it. If the key in fact asks for confirmation, the agent's dialog can still appear.";

/// A pretty rendering of a read's data.
fn pretty(v: &serde_json::Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

/// One read (never starts the runtime), rendered.
async fn read(
    ctx: &Ctx,
    subject: InspectSubject,
    pick: impl Fn(serde_json::Value) -> Result<serde_json::Value, Outcome>,
) -> Outcome {
    let mut client = match session(ctx, false).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    match inspect(&mut client, subject).await.and_then(pick) {
        Ok(data) => {
            let human = pretty(&data);
            Outcome::of(Envelope::ok(data)).with_human(human)
        }
        Err(o) => o,
    }
}

/// One catalog request on a session that may start the runtime.
async fn send(ctx: &Ctx, request: CatalogRequest) -> Outcome {
    if let Err(e) = request.validate() {
        return usage(&e.to_string());
    }
    let mut client = match session(ctx, true).await {
        Ok(c) => c,
        Err(o) => return o,
    };
    let env = client.request(Request::Catalog(request)).await;
    let human = if env.code.is_success() {
        pretty(&env.data)
    } else {
        String::new()
    };
    Outcome::of(env).with_human(human)
}

fn not_found(what: &str) -> Outcome {
    Outcome::of(failure(Code::NotFound, &format!("no such {what}"), None))
}

/// The item of `items` (under `key`) whose `id_key` or `alias` equals `wanted`.
fn find(
    data: &serde_json::Value,
    key: &str,
    id_key: &str,
    wanted: &str,
) -> Option<serde_json::Value> {
    data.get("items")
        .or_else(|| data.get(key))?
        .as_array()?
        .iter()
        .find(|d| {
            d.get(id_key).and_then(|v| v.as_str()) == Some(wanted)
                || d.get("alias").and_then(|v| v.as_str()) == Some(wanted)
                || d.get("id").and_then(|v| v.as_str()) == Some(wanted)
        })
        .cloned()
}

/// A destination's ID from its ID or alias (the catalog listing, read-only).
async fn destination_id(ctx: &Ctx, wanted: &str) -> Result<DestinationId, Outcome> {
    if let Ok(mut client) = session(ctx, false).await
        && let Ok(data) = inspect(&mut client, InspectSubject::Destinations).await
        && let Some(d) = find(&data, "destinations", "destination_id", wanted)
        && let Some(id) = d
            .get("destination_id")
            .or_else(|| d.get("id"))
            .and_then(|v| v.as_str())
    {
        return DestinationId::parse(id).map_err(|_| usage("invalid destination ID"));
    }
    DestinationId::parse(wanted).map_err(|_| usage("invalid destination ID or alias"))
}

// --- destination -------------------------------------------------------------------------

/// Handle `destination`.
pub(crate) fn destination(ctx: &Ctx, command: DestinationCommand) -> ExitCode {
    block(ctx, destination_flow(ctx, command))
}

async fn destination_flow(ctx: &Ctx, command: DestinationCommand) -> Outcome {
    match command {
        // M03 wave 0: `dispatch` answers `prefer` first; this arm keeps the match
        // exhaustive and answers the same way (U12 fills the handler).
        DestinationCommand::Prefer(_) => crate::m03_cmd::not_available_outcome(),
        DestinationCommand::List => read(ctx, InspectSubject::Destinations, Ok).await,
        DestinationCommand::Show { destination } => {
            read(ctx, InspectSubject::Destinations, |data| {
                find(&data, "destinations", "destination_id", &destination)
                    .ok_or_else(|| not_found("destination"))
            })
            .await
        }
        DestinationCommand::Remove {
            destination,
            request_id: given,
        } => {
            let id = match destination_id(ctx, &destination).await {
                Ok(id) => id,
                Err(o) => return o,
            };
            let rid = match request_id(given.as_deref()) {
                Ok(r) => r,
                Err(o) => return o,
            };
            send(
                ctx,
                CatalogRequest::RemoveDestination {
                    id,
                    request_id: rid,
                },
            )
            .await
        }
        DestinationCommand::Add(a) => match destination_spec(ctx, &a).await {
            Ok(spec) => {
                let rid = match request_id(a.request_id.as_deref()) {
                    Ok(r) => r,
                    Err(o) => return o,
                };
                send(
                    ctx,
                    CatalogRequest::UpsertDestination {
                        destination: spec,
                        request_id: rid,
                    },
                )
                .await
            }
            Err(o) => o,
        },
    }
}

/// The destination `add` names: `--id`, else the catalog's ID for the alias, else
/// `dst-<alias>`.
async fn destination_spec(ctx: &Ctx, a: &DestinationAddArgs) -> Result<DestinationSpec, Outcome> {
    let id = match &a.id {
        Some(id) => DestinationId::parse(id).map_err(|_| usage("invalid destination ID"))?,
        None => match destination_id(ctx, &a.alias).await {
            Ok(id) => id,
            Err(_) => DestinationId::parse(&format!("dst-{}", a.alias))
                .map_err(|_| usage("give --id: the alias does not make a destination ID"))?,
        },
    };
    let definition = if a.observed {
        DestinationDefinitionSpec::Observed
    } else {
        let hostname = a
            .hostname
            .clone()
            .ok_or_else(|| usage("--hostname or --observed"))?;
        let account = a
            .account
            .as_deref()
            .ok_or_else(|| usage("a managed destination needs --account"))
            .and_then(|s| AccountName::parse(s).map_err(|_| usage("invalid --account")))?;
        let identity = a
            .identity
            .as_deref()
            .ok_or_else(|| usage("a managed destination needs --identity"))
            .and_then(|s| IdentityId::parse(s).map_err(|_| usage("invalid --identity")))?;
        DestinationDefinitionSpec::Managed {
            hostname,
            port: a.port,
            account,
            identity,
        }
    };
    Ok(DestinationSpec {
        id,
        alias: a.alias.clone(),
        definition,
        label: a.label.clone(),
    })
}

// --- identity ----------------------------------------------------------------------------

/// Handle `identity`.
pub(crate) fn identity(ctx: &Ctx, command: IdentityCommand) -> ExitCode {
    block(ctx, identity_flow(ctx, command))
}

fn identity_id(s: &str) -> Result<IdentityId, Outcome> {
    IdentityId::parse(s).map_err(|_| usage("invalid identity ID"))
}

async fn identity_flow(ctx: &Ctx, command: IdentityCommand) -> Outcome {
    match command {
        IdentityCommand::List => read(ctx, InspectSubject::Identities, Ok).await,
        IdentityCommand::Remove {
            identity,
            request_id: given,
        } => {
            let (id, rid) = match (identity_id(&identity), request_id(given.as_deref())) {
                (Ok(i), Ok(r)) => (i, r),
                (Err(o), _) | (_, Err(o)) => return o,
            };
            send(
                ctx,
                CatalogRequest::RemoveIdentity {
                    id,
                    request_id: rid,
                },
            )
            .await
        }
        IdentityCommand::WithdrawDeclaration {
            identity,
            request_id: given,
        } => {
            let (id, rid) = match (identity_id(&identity), request_id(given.as_deref())) {
                (Ok(i), Ok(r)) => (i, r),
                (Err(o), _) | (_, Err(o)) => return o,
            };
            send(
                ctx,
                CatalogRequest::WithdrawDeclaration {
                    identity: id,
                    revision: None,
                    reason: WithdrawReason::Owner,
                    request_id: rid,
                },
            )
            .await
        }
        IdentityCommand::DeclareInteraction {
            identity,
            interaction: _,
            request_id: given,
        } => {
            let (id, rid) = match (identity_id(&identity), request_id(given.as_deref())) {
                (Ok(i), Ok(r)) => (i, r),
                (Err(o), _) | (_, Err(o)) => return o,
            };
            let mut client = match session(ctx, true).await {
                Ok(c) => c,
                Err(o) => return o,
            };
            declare(&mut client, &mut TerminalPrompt, ctx, id, rid).await
        }
        IdentityCommand::Adopt(a) => adopt(ctx, a).await,
    }
}

/// `declare-interaction <id> none` on a connected session (module docs).
pub(crate) async fn declare<S: Session, P: Prompter>(
    s: &mut S,
    p: &mut P,
    ctx: &Ctx,
    identity: IdentityId,
    rid: heimdall_contract::ids::RequestId,
) -> Outcome {
    let request = Request::Catalog(CatalogRequest::DeclareInteraction {
        identity: identity.clone(),
        interaction: DeclaredInteraction::None,
        request_id: rid,
    });
    let preface =
        format!("Declare that identity {identity} needs no interaction.\n{DECLARATION_TEXT}\n");
    if !ctx.json && !ctx.interactive() {
        crate::output::diagnostic(&preface);
    }
    let env = decided_request(s, p, ctx, request, &preface, None).await;
    let human = if env.code.is_success() {
        pretty(&env.data)
    } else {
        String::new()
    };
    Outcome::of(env).with_human(human)
}

/// The one `.pub` line of `path` (bounded; never private material).
fn read_public_key(path: &Path) -> Result<String, Outcome> {
    use std::io::Read as _;
    let file = std::fs::File::open(path).map_err(|_| usage("the --pub file cannot be read"))?;
    let mut text = String::new();
    file.take(MAX_PUBLIC_KEY_BYTES as u64 + 1)
        .read_to_string(&mut text)
        .map_err(|_| usage("the --pub file is not UTF-8 text"))?;
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    match lines.as_slice() {
        [line] if !line.contains("PRIVATE KEY") && text.len() <= MAX_PUBLIC_KEY_BYTES => {
            Ok(line.trim().to_owned())
        }
        _ => Err(usage(
            "the --pub file must hold exactly one OpenSSH public-key line",
        )),
    }
}

/// An OpenSSH public-key line from an agent's key blob (padded base64).
fn public_line(key_type: &str, blob: &[u8]) -> String {
    let mut b64 = heimdall_localenv::known_hosts::base64_encode_unpadded(blob);
    while !b64.len().is_multiple_of(4) {
        b64.push('=');
    }
    format!("{key_type} {b64}")
}

async fn adopt(ctx: &Ctx, a: IdentityAdoptArgs) -> Outcome {
    let rid = match request_id(a.request_id.as_deref()) {
        Ok(r) => r,
        Err(o) => return o,
    };
    if let Some(path) = &a.pub_file {
        let key = match read_public_key(path) {
            Ok(k) => k,
            Err(o) => return o,
        };
        let shown = std::path::absolute(path).unwrap_or_else(|_| path.clone());
        return send(
            ctx,
            CatalogRequest::AdoptIdentity {
                identity: IdentitySpec {
                    source: IdentitySourceSpec::PublicKeyFile {
                        path: shown.to_string_lossy().into_owned(),
                    },
                    public_key: key,
                    label: a.label.clone(),
                },
                request_id: rid,
            },
        )
        .await;
    }
    adopt_from_agent(ctx, &a, rid, &mut TerminalPrompt).await
}

/// `identity adopt --from-agent` (module docs).
async fn adopt_from_agent<P: Prompter>(
    ctx: &Ctx,
    a: &IdentityAdoptArgs,
    rid: heimdall_contract::ids::RequestId,
    p: &mut P,
) -> Outcome {
    match a.active_probe.as_deref() {
        None | Some("agent") => {}
        Some(_) => return usage("--active-probe for an agent listing is `agent`"),
    }
    let local = match crate::doctor_cmd::local_context(ctx) {
        Ok(l) => l,
        Err(o) => return o,
    };
    let agents = heimdall_localenv::agents::detect_agents(&local.env, &local.paths, local.platform);
    let Some(agent) = agents.iter().find(|e| {
        e.presence == heimdall_localenv::agents::Presence::Present
            && matches!(
                e.source,
                heimdall_localenv::agents::EndpointSource::SshAuthSock
            )
    }) else {
        return Outcome::of(failure(
            Code::ServiceUnavailable,
            "no agent is reachable at SSH_AUTH_SOCK; adopt with --pub FILE instead",
            Some(heimdall_contract::envelope::reason::ENDPOINT_ABSENT),
        ));
    };
    let display = agent.locator.display(&local.paths.account_home);
    if ctx.non_interactive {
        if a.active_probe.is_none() {
            return Outcome::of(failure(
                Code::InteractionRequired,
                "listing an agent is the explicit `agent` probe: under --non-interactive pass --active-probe agent",
                None,
            ));
        }
    } else if !ctx.interactive() {
        return Outcome::of(not_confirmed(None, None, non_interactive_reason(ctx)));
    } else {
        let text = format!(
            "List the identities of the {} agent at {display}?\nThis is the explicit `agent` probe: one identity-listing request, nothing signed, added or removed.\n",
            serde_json::to_value(agent.provider)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned()),
        );
        let answer = p.ask(&text).await;
        if answer != Answer::Yes {
            return Outcome::of(not_confirmed(None, None, answer.reason()));
        }
    }
    let pctx = heimdall_localenv::probe::ProbeContext::new(&local, false, ctx.interactive());
    let (_record, listing) =
        heimdall_localenv::probe::agent::list_identities_observed(&pctx, &agent.locator);
    let Ok(listing) = listing else {
        return Outcome::of(failure(
            Code::ServiceUnavailable,
            "the agent could not be listed",
            None,
        ));
    };
    let endpoint = match &agent.locator {
        heimdall_localenv::agents::EndpointLocator::UnixSocket(p) => EndpointRef {
            kind: EndpointKind::UnixSocket,
            locator: p.to_string_lossy().into_owned(),
        },
        heimdall_localenv::agents::EndpointLocator::NamedPipe(n) => EndpointRef {
            kind: EndpointKind::NamedPipe,
            locator: n.clone(),
        },
    };
    let listed: BTreeSet<String> = listing
        .identities
        .iter()
        .map(|i| i.fingerprint.clone())
        .collect();
    // Lapses first, on a session only if the runtime is already running.
    let mut notes = Vec::new();
    let running = crate::client::connect(ctx, false).await.ok();
    let lapses = lapses_at(ctx, &endpoint, &listed);
    let mut client = running;
    for (identity, revision) in lapses {
        let mut recorded = false;
        if let Some(c) = client.as_mut()
            && let Ok(r) = request_id(None)
        {
            let env = c
                .request(Request::Catalog(CatalogRequest::WithdrawDeclaration {
                    identity: identity.clone(),
                    revision: Some(revision),
                    reason: WithdrawReason::ListingMissing,
                    request_id: r,
                }))
                .await;
            recorded = env.code.is_success();
        }
        notes.push(serde_json::json!({
            "identity_id": identity,
            "lapsed": true,
            "recorded": recorded,
            "command": (!recorded).then(|| format!("heimdall identity withdraw-declaration {identity}")),
        }));
    }
    let chosen = match choose_listed(&listing.identities, a.fingerprint.as_deref()) {
        Ok(c) => c,
        Err(o) => return o,
    };
    let request = CatalogRequest::AdoptIdentity {
        identity: IdentitySpec {
            source: IdentitySourceSpec::NativeAgent { endpoint },
            public_key: public_line(&chosen.key_type, &chosen.public_blob),
            label: a.label.clone(),
        },
        request_id: rid,
    };
    let mut out = send(ctx, request).await;
    if let serde_json::Value::Object(map) = &mut out.env.data
        && !notes.is_empty()
    {
        map.insert("lapses".to_owned(), serde_json::Value::Array(notes));
    }
    out
}

/// ⟨M02⟩ ADR-0007 §12.30 item 12: the one listed identity `identity adopt --from-agent`
/// adopts. With `--fingerprint`, the listed identity with exactly that fingerprint
/// (`NOT_FOUND` when the agent lists none: the given value is never echoed, the listed
/// fingerprints are named instead); without it, the only one listed (several: a usage
/// error naming their fingerprints and both ways to choose one).
fn choose_listed<'a>(
    listed: &'a [heimdall_ipc::agent_client::AgentIdentity],
    fingerprint: Option<&str>,
) -> Result<&'a heimdall_ipc::agent_client::AgentIdentity, Outcome> {
    let fps = || {
        listed
            .iter()
            .map(|i| i.fingerprint.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(wanted) = fingerprint {
        return listed
            .iter()
            .find(|i| i.fingerprint == wanted)
            .ok_or_else(|| {
                Outcome::of(failure(
                    Code::NotFound,
                    &format!(
                        "the agent lists no identity with that fingerprint (it lists: {}); nothing was adopted",
                        if listed.is_empty() { "none".to_owned() } else { fps() }
                    ),
                    None,
                ))
            });
    }
    match listed {
        [one] => Ok(one),
        [] => Err(Outcome::of(failure(
            Code::NotFound,
            "the agent lists no identity",
            None,
        ))),
        many => Err(usage(&format!(
            "the agent lists {} identities ({}); choose one with --fingerprint <FINGERPRINT>, or adopt it with --pub FILE",
            many.len(),
            fps()
        ))),
    }
}

/// Declared identities at `endpoint` (in force now) whose fingerprint `listed` lacks,
/// with their declaration revision (the store, read-only).
fn lapses_at(
    ctx: &Ctx,
    endpoint: &EndpointRef,
    listed: &BTreeSet<String>,
) -> Vec<(IdentityId, u64)> {
    let Ok(store) = crate::doctor_cmd::open_store(ctx) else {
        return Vec::new();
    };
    let now = heimdall_contract::Timestamp::now();
    store
        .transaction(|tx| {
            let mut out = Vec::new();
            for i in tx.identities()? {
                if i.source.endpoint() == Some(endpoint)
                    && !listed.contains(&i.fingerprint)
                    && let Some(d) = tx.interaction_declaration(&i.id)?
                    && d.counts_for(&i, endpoint, now)
                {
                    out.push((i.id.clone(), d.revision));
                }
            }
            Ok(out)
        })
        .unwrap_or_default()
}

// --- profile -----------------------------------------------------------------------------

/// Handle `profile`.
pub(crate) fn profile(ctx: &Ctx, command: ProfileCommand) -> ExitCode {
    block(ctx, profile_flow(ctx, command))
}

fn profile_id(s: &str) -> Result<ProfileId, Outcome> {
    ProfileId::parse(s).map_err(|_| usage("invalid profile ID"))
}

fn pair(s: &str) -> Result<AccessPairRef, Outcome> {
    let (d, a) = s
        .split_once(':')
        .ok_or_else(|| usage("a pair is DEST:ACCOUNT"))?;
    Ok(AccessPairRef {
        destination: DestinationId::parse(d).map_err(|_| usage("invalid destination"))?,
        account: AccountName::parse(a).map_err(|_| usage("invalid account"))?,
    })
}

fn pairs(list: &[String]) -> Result<BTreeSet<AccessPairRef>, Outcome> {
    list.iter().map(|p| pair(p)).collect()
}

/// The stored profile (`inspect profiles`): its pairs and label.
async fn stored_profile(
    ctx: &Ctx,
    id: &ProfileId,
) -> Result<(BTreeSet<AccessPairRef>, Option<String>), Outcome> {
    let mut client = session(ctx, true).await?;
    let data = inspect(&mut client, InspectSubject::Profiles).await?;
    let item = data
        .get("items")
        .or_else(|| data.get("profiles"))
        .and_then(|v| v.as_array())
        .and_then(|items| {
            items
                .iter()
                .find(|p| {
                    p.get("profile_id")
                        .or_else(|| p.get("id"))
                        .and_then(|v| v.as_str())
                        == Some(id.as_str())
                })
                .cloned()
        })
        .ok_or_else(|| not_found("profile"))?;
    let scope = item.get("scope").cloned().unwrap_or_default();
    let raw = scope
        .get("pairs")
        .or_else(|| item.get("pairs"))
        .cloned()
        .unwrap_or_default();
    let pairs: BTreeSet<AccessPairRef> = serde_json::from_value(raw).unwrap_or_default();
    let label = item
        .get("label")
        .and_then(|l| l.as_str())
        .map(str::to_owned);
    Ok((pairs, label))
}

async fn profile_flow(ctx: &Ctx, command: ProfileCommand) -> Outcome {
    match command {
        ProfileCommand::List => read(ctx, InspectSubject::Profiles, Ok).await,
        ProfileCommand::Show { profile } => {
            read(ctx, InspectSubject::Profiles, |data| {
                data.get("items")
                    .or_else(|| data.get("profiles"))
                    .and_then(|v| v.as_array())
                    .and_then(|items| {
                        items
                            .iter()
                            .find(|p| {
                                p.get("profile_id")
                                    .or_else(|| p.get("id"))
                                    .and_then(|v| v.as_str())
                                    == Some(profile.as_str())
                            })
                            .cloned()
                    })
                    .ok_or_else(|| not_found("profile"))
            })
            .await
        }
        ProfileCommand::Create {
            profile,
            pairs: list,
            label,
            request_id: given,
        } => {
            let built = (|| {
                Ok::<_, Outcome>((
                    profile_id(&profile)?,
                    pairs(&list)?,
                    request_id(given.as_deref())?,
                ))
            })();
            match built {
                Ok((id, pairs, rid)) => {
                    send(
                        ctx,
                        CatalogRequest::UpsertProfile {
                            profile: ProfileSpec { id, pairs, label },
                            request_id: rid,
                        },
                    )
                    .await
                }
                Err(o) => o,
            }
        }
        ProfileCommand::Add {
            profile,
            pairs: list,
            request_id: given,
        } => edit_pairs(ctx, &profile, &list, given.as_deref(), true).await,
        ProfileCommand::Remove {
            profile,
            pairs: list,
            request_id: given,
        } if !list.is_empty() => edit_pairs(ctx, &profile, &list, given.as_deref(), false).await,
        ProfileCommand::Remove {
            profile,
            request_id: given,
            ..
        } => {
            let built =
                (|| Ok::<_, Outcome>((profile_id(&profile)?, request_id(given.as_deref())?)))();
            match built {
                Ok((id, rid)) => {
                    send(
                        ctx,
                        CatalogRequest::RemoveProfile {
                            id,
                            request_id: rid,
                        },
                    )
                    .await
                }
                Err(o) => o,
            }
        }
    }
}

/// `profile add` (`adding`) or `profile remove --pair`: the stored pairs with `list`
/// added or removed, as an upsert (the profile's revision grows; existing grants keep
/// theirs).
async fn edit_pairs(
    ctx: &Ctx,
    profile: &str,
    list: &[String],
    given: Option<&str>,
    adding: bool,
) -> Outcome {
    let built = (|| Ok::<_, Outcome>((profile_id(profile)?, pairs(list)?, request_id(given)?)))();
    let (id, delta, rid) = match built {
        Ok(b) => b,
        Err(o) => return o,
    };
    let (mut current, label) = match stored_profile(ctx, &id).await {
        Ok(p) => p,
        Err(o) => return o,
    };
    if adding {
        current.extend(delta);
    } else {
        current.retain(|p| !delta.contains(p));
    }
    send(
        ctx,
        CatalogRequest::UpsertProfile {
            profile: ProfileSpec {
                id,
                pairs: current,
                label,
            },
            request_id: rid,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_ipc::agent_client::AgentIdentity;

    fn listed(n: u8) -> AgentIdentity {
        AgentIdentity {
            key_type: "ssh-ed25519".to_owned(),
            fingerprint: format!("SHA256:fixture-{n}"),
            public_blob: vec![n; 4],
        }
    }

    /// ADR-0007 §12.30 item 12: `identity adopt --from-agent --fingerprint <fp>` adopts
    /// exactly the listed identity with that fingerprint; an unlisted one is `NOT_FOUND`
    /// (the given value never echoed); without it, several listed is a usage error that
    /// names their fingerprints and `--fingerprint`, and one listed is adopted.
    #[test]
    fn from_agent_fingerprint_chooses_one_listed_identity() {
        let many = [listed(1), listed(2), listed(3)];
        let chosen = choose_listed(&many, Some("SHA256:fixture-2"))
            .unwrap_or_else(|o| panic!("{:?}", o.env.code));
        assert_eq!(chosen, &many[1]);
        let Err(missing) = choose_listed(&many, Some("SHA256:HEIMDALL_CANARY_not-listed")) else {
            panic!("an unlisted fingerprint is refused");
        };
        assert_eq!(missing.env.code, Code::NotFound);
        let text = serde_json::to_string(&missing.env).unwrap_or_default();
        assert!(!text.contains("HEIMDALL_CANARY"), "{text}");
        assert!(text.contains("SHA256:fixture-3"), "{text}");
        let Err(several) = choose_listed(&many, None) else {
            panic!("several listed need a choice");
        };
        assert_eq!(several.env.code, Code::UsageError);
        let text = serde_json::to_string(&several.env).unwrap_or_default();
        assert!(
            text.contains("--fingerprint") && text.contains("SHA256:fixture-1"),
            "{text}"
        );
        let one = [listed(7)];
        assert_eq!(choose_listed(&one, None).ok(), Some(&one[0]));
        assert_eq!(
            choose_listed(&[], None).err().map(|o| o.env.code),
            Some(Code::NotFound)
        );
        // `--fingerprint` needs `--from-agent`: with `--pub`, or alone, it does not parse.
        use clap::Parser as _;
        for line in [
            &[
                "identity",
                "adopt",
                "--pub",
                "k.pub",
                "--fingerprint",
                "SHA256:x",
            ][..],
            &["identity", "adopt", "--fingerprint", "SHA256:x"],
        ] {
            let argv = std::iter::once("heimdall").chain(line.iter().copied());
            assert!(crate::cli::Cli::try_parse_from(argv).is_err(), "{line:?}");
        }
    }
}
