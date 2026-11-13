//! Human renderings of the enrollment commands (m03-plan U12; ADR-0008 D5). Every
//! string reaches the terminal through `output::{diagnostic, emit_rendered}`, which
//! sanitize it; nothing here prints.
//!
//! The wording of the plan's disclosures is this module's (the runtime sends their
//! kinds only, ADR-0008 D5 §6.1); the `slot_free` command is
//! `heimdall_localenv::projection::plan::slot_free_command` (R3), never retyped.

use heimdall_contract::enrollment::{
    ApprovedTarget, DisclosureKind, EnrollmentForm, EnrollmentNoteKind, EnrollmentPlan,
    EnrollmentResult, EnrollmentState, TargetSummary,
};
use heimdall_localenv::projection::plan::slot_free_command;

/// The CA public key of a plan's exact line (`cert-authority,principals="…" <type>
/// <blob> heimdall:enr_…`), as the runtime cuts it for `EnrollSystemForm`.
#[must_use]
pub(super) fn ca_key_of_line(line: &str) -> &str {
    line.split_once(' ')
        .map_or("", |(_, rest)| rest)
        .rsplit_once(' ')
        .map_or("", |(k, _)| k)
}

/// The system form's lines for a plan (ADR-0008 D5 §6.9): the owner installs them;
/// Heimdall never edits `sshd_config`.
#[must_use]
pub(super) fn system_lines(plan: &EnrollmentPlan) -> heimdall_domain::decision::SystemFormLines {
    heimdall_app::enrollment::system_form_lines(
        ca_key_of_line(&plan.line),
        &plan.verification.positive_principal,
    )
}

/// One disclosure, in words (ADR-0008 D5 §6.1).
#[must_use]
pub(crate) fn disclosure_text(kind: DisclosureKind, alias: &str) -> String {
    match kind {
        DisclosureKind::ConfigCommandsRunAsOrdinaryUse => format!(
            "every step connects with your ssh configuration for `{alias}` for everything \
             that is not pinned, so its `Match exec` and similar entries run as in ordinary use"
        ),
        DisclosureKind::CaTrustBlastRadius => "the CA trust on this account lets this device's \
             issuer mint certificates for this principal: whoever holds the CA's key can reach \
             every account that trusts it"
            .to_owned(),
        DisclosureKind::RemoveWindow => "the enrollment can be removed early (`heimdall enroll \
             remove`); certificates already issued under this CA stay valid until they expire \
             (the pair residual)"
            .to_owned(),
        DisclosureKind::LockContinuityOnce => "managed signing continues while your desktop is \
             locked, within each grant's deadline"
            .to_owned(),
        DisclosureKind::ReconcileMayStopOwnStaleScript => "`heimdall enroll reconcile` may stop \
             Heimdall's own stale script on the destination (TERM, then KILL, of the exact \
             process group its lock recorded); nothing else is ever signalled"
            .to_owned(),
        DisclosureKind::OrdinarySshNeedsHeldSlot => format!(
            "ordinary `ssh {alias}` works only while a binding holds this alias's managed slot; \
             `{}` holds one while it runs",
            slot_free_command(alias)
        ),
        _ => "see the decision's recorded disclosures".to_owned(),
    }
}

/// The wire name of a serializable enum value (`snake_case`).
fn wire<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_owned))
        .unwrap_or_else(|| "?".to_owned())
}

/// The approved target on one line.
#[must_use]
pub(super) fn target_line(t: &ApprovedTarget) -> String {
    format!(
        "{}:{} user {}, no proxy, host key {} {}",
        t.hostname, t.port, t.user, t.host_key.algorithm, t.host_key.fingerprint
    )
}

/// The host-key change of a target, as a diff of the approved key against the
/// proposed (or freshly evaluated) one (ADR-0008 D5 §6.2 `held` row, §6.8).
#[must_use]
pub(super) fn key_diff(approved: &ApprovedTarget, proposed: &ApprovedTarget) -> String {
    let mut out = format!(
        "Host key change for {}:{} (user {}):\n",
        proposed.hostname, proposed.port, proposed.user
    );
    out.push_str(&format!(
        "- {} {} {} (approved)\n",
        approved.host_key.algorithm, approved.host_key.key, approved.host_key.fingerprint
    ));
    out.push_str(&format!(
        "+ {} {} {} (now presented)\n",
        proposed.host_key.algorithm, proposed.host_key.key, proposed.host_key.fingerprint
    ));
    if (approved.hostname.as_str(), approved.port, &approved.user)
        != (proposed.hostname.as_str(), proposed.port, &proposed.user)
    {
        out.push_str(&format!(
            "- route {}:{} user {}\n+ route {}:{} user {}\n",
            approved.hostname,
            approved.port,
            approved.user,
            proposed.hostname,
            proposed.port,
            proposed.user
        ));
    }
    out
}

/// A removal's freshly evaluated target against the listed approved one (ADR-0008 D5
/// §6.8): the host-key fingerprint the record approved and the key now presented.
#[must_use]
pub(super) fn summary_diff(approved: Option<&TargetSummary>, fresh: &ApprovedTarget) -> String {
    let mut out = format!(
        "Host key change for {}:{} (user {}):\n",
        fresh.hostname, fresh.port, fresh.user
    );
    match approved {
        Some(a) => out.push_str(&format!(
            "- {} (approved; {}:{} user {})\n",
            a.host_key_fingerprint, a.hostname, a.port, a.user
        )),
        None => out.push_str("- (the approved key is not listed)\n"),
    }
    out.push_str(&format!(
        "+ {} {} {} (freshly evaluated)\n",
        fresh.host_key.algorithm, fresh.host_key.key, fresh.host_key.fingerprint
    ));
    out
}

/// The full preview (ADR-0008 D5 §6.1): everything the decision covers, the
/// disclosures, and the exact line (account form) or the lines the owner installs
/// (system form).
#[must_use]
pub(super) fn preview(plan: &EnrollmentPlan) -> String {
    let mut out = format!(
        "Enrollment preview for {} ({}), account {}, form {}\n",
        plan.alias,
        plan.destination_id,
        plan.account,
        wire(&plan.form)
    );
    match plan.form {
        EnrollmentForm::System => {
            let lines = system_lines(plan);
            out.push_str(
                "  Heimdall writes nothing on the destination: you install these lines yourself \
                 (Heimdall never edits sshd_config, never runs sudo):\n",
            );
            out.push_str(&format!(
                "    TrustedUserCAKeys file line: {}\n",
                lines.trusted_user_ca_keys_line
            ));
            out.push_str(&format!(
                "    AuthorizedPrincipalsFile line for {}: {}\n",
                plan.account, lines.principals_line
            ));
            for d in &lines.sshd_directives {
                out.push_str(&format!("    sshd_config: {d}\n"));
            }
        }
        _ => {
            out.push_str(&format!(
                "  registry: {} ({})\n",
                plan.registry.path_display,
                wire(&plan.registry.resolved_by)
            ));
            out.push_str("  exact line to be written:\n");
            out.push_str(&format!("    {}\n", plan.line));
        }
    }
    out.push_str(&format!("  line SHA-256: {}\n", plan.line_sha256));
    out.push_str(&format!("  CA: {}\n", plan.ca_fingerprint));
    out.push_str(&format!(
        "  approved target: {}\n",
        target_line(&plan.approved_target)
    ));
    let ea = &plan.existing_access;
    out.push_str(&format!(
        "  existing access: {} identity {} through {} ({})\n",
        ea.mechanism,
        ea.identity_id,
        ea.endpoint,
        wire(&ea.endpoint_source)
    ));
    out.push_str(&format!(
        "    every remote step runs: ssh {} -T {}\n",
        ea.invocation.join(" "),
        plan.alias
    ));
    out.push_str(&format!(
        "  host-trust pins: {}\n",
        plan.host_trust.join(" ")
    ));
    if plan.bootstrap.is_some() {
        out.push_str(
            "  bootstrap: if the registry's directory is absent, create it with mode 0700\n",
        );
    }
    out.push_str(&format!(
        "  verification: positive principal {}, negative attempt {}, certificates valid at most {} s\n",
        plan.verification.positive_principal,
        if plan.verification.negative { "yes" } else { "no" },
        plan.verification.max_validity_seconds
    ));
    out.push_str(&format!("  rollback: {}\n", wire(&plan.rollback)));
    out.push_str("  disclosures:\n");
    for d in &plan.disclosures {
        out.push_str(&format!(
            "    * {}: {}\n",
            wire(d),
            disclosure_text(*d, &plan.alias)
        ));
    }
    out.push_str(&format!("  plan digest: {}\n", plan.plan_digest));
    out
}

/// What a state means for the owner, in one line (never "removed" unless it is).
#[must_use]
pub(super) fn state_line(id: &str, state: EnrollmentState, form: Option<EnrollmentForm>) -> String {
    let system = form == Some(EnrollmentForm::System);
    let s = state.as_str();
    match state {
        EnrollmentState::Removed if system => {
            format!("enrollment {id}: {s} (absence verified)")
        }
        EnrollmentState::ManualRemovalPending => format!(
            "enrollment {id}: {s}: NOT removed. Delete the lines below, then run \
             `heimdall enroll verify {id} --absence`; it is recorded removed only after \
             that absence check passes"
        ),
        EnrollmentState::RemovalVerifying => {
            format!("enrollment {id}: {s}: the absence check runs; not removed yet")
        }
        EnrollmentState::ManualPending => format!(
            "enrollment {id}: {s}: apply the lines below on the destination, then run \
             `heimdall enroll verify {id}`"
        ),
        _ => format!("enrollment {id}: {s}"),
    }
}

/// An enrollment result (`apply`, `verify`, `remove`, `reconcile`, `abandon`).
#[must_use]
pub(super) fn result(r: &EnrollmentResult, form: Option<EnrollmentForm>) -> String {
    let id = r.enrollment_id.to_string();
    let mut out = state_line(&id, r.state, form);
    out.push('\n');
    if let Some(at) = &r.verified_at {
        out.push_str(&format!("  verified at {at}\n"));
    }
    if let Some(e) = &r.evidence {
        out.push_str(&format!(
            "  evidence: client {}, server {}, operation {}\n",
            e.client, e.server, e.operation_id
        ));
    }
    if let Some(n) = &r.next {
        out.push_str(&format!("  next: {}\n", wire(n)));
    }
    for c in &r.commands {
        out.push_str(&format!("    {c}\n"));
    }
    if !r.instructions.is_empty() {
        out.push_str("  instructions:\n");
        for i in &r.instructions {
            out.push_str(&format!("    {i}\n"));
        }
    }
    for n in &r.notes {
        let text = match n.kind {
            EnrollmentNoteKind::OrdinarySshNeedsHeldSlot => {
                "ordinary ssh to this alias works only while a binding holds its managed slot"
                    .to_owned()
            }
            EnrollmentNoteKind::PossibleLateWrite => "possible_late_write: an uncertain append \
                 may still land until its not-after passes; it is listed until an inspect shows \
                 it absent"
                .to_owned(),
            _ => wire(&n.kind),
        };
        match &n.command {
            Some(c) => out.push_str(&format!("  note: {text}: `{c}`\n")),
            None => out.push_str(&format!("  note: {text}\n")),
        }
    }
    out
}

/// The owner's next step for a held record's reason (ADR-0008 D5 §6.2 `held` row).
#[must_use]
pub(super) fn held_next(reason: Option<&str>, id: &str, op: Option<&str>) -> Vec<String> {
    let op = op.unwrap_or("<operation>");
    match reason {
        Some("host_key_changed") => vec![
            format!("heimdall enroll verify {id} --approve-target-change"),
            format!("heimdall enroll remove {id}"),
        ],
        Some("principals_not_enforced" | "positive_refused") => vec![
            format!("heimdall enroll verify {id}"),
            format!("heimdall enroll remove {id}"),
        ],
        Some("lock_holder_unresolved") => vec![
            "check the lock's holder process on the destination and remove the lock link by hand"
                .to_owned(),
            format!("heimdall enroll reconcile {op} --after-manual-recovery"),
        ],
        Some(_) => vec![
            format!("heimdall enroll remove {id}"),
            format!("heimdall enroll abandon {id}"),
        ],
        None => vec![
            format!("heimdall enroll verify {id} --approve-target-change (a host-key change)"),
            format!("heimdall enroll verify {id} (an evidence-based hold)"),
            format!("heimdall enroll remove {id}"),
            format!("heimdall enroll abandon {id}"),
        ],
    }
}

/// `enroll status` (inspect enrollments): every record's state and marker; a verified
/// one's `slot_free` command; the `late_write` residual; a held record's reason and
/// next step. `aliases` maps destination IDs to aliases (`inspect destinations`).
#[must_use]
pub(super) fn status(view: &serde_json::Value, aliases: &dyn Fn(&str) -> Option<String>) -> String {
    let text = |v: &serde_json::Value, k: &str| {
        v.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let list = view
        .get("enrollments")
        .and_then(serde_json::Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if list.is_empty() {
        return "no enrollments\n".to_owned();
    }
    let mut out = String::new();
    for e in list {
        let id = text(e, "enrollment_id");
        let dest = text(e, "destination_id");
        let state = text(e, "state");
        let alias = aliases(&dest);
        out.push_str(&format!(
            "{id} {state} marker {} destination {}{} account {} form {}\n",
            text(e, "marker"),
            dest,
            alias
                .as_deref()
                .map(|a| format!(" ({a})"))
                .unwrap_or_default(),
            text(e, "account"),
            text(e, "form"),
        ));
        if let Some(r) = e.get("registry") {
            out.push_str(&format!("  registry: {}\n", text(r, "path_display")));
        }
        if let Some(at) = e.get("verified_at").and_then(serde_json::Value::as_str) {
            out.push_str(&format!("  verified at {at}\n"));
        }
        if let Some(at) = e
            .get("evidence_fresh_until")
            .and_then(serde_json::Value::as_str)
        {
            out.push_str(&format!("  evidence fresh until {at}\n"));
        }
        if state == "verified" {
            let a = alias.clone().unwrap_or_else(|| "<alias>".to_owned());
            out.push_str(&format!(
                "  slot_free: ordinary `ssh {a}` works only while a binding holds this alias's managed slot; `{}` holds one while it runs\n",
                slot_free_command(&a)
            ));
        }
        if e.get("possible_late_write")
            .and_then(serde_json::Value::as_bool)
            == Some(true)
        {
            out.push_str(
                "  possible_late_write: an uncertain append may still land until its not-after \
                 passes (the late_write residual); listed until an inspect shows it absent\n",
            );
        }
        if let Some(p) = e.get("removal_purpose").and_then(serde_json::Value::as_str) {
            out.push_str(&format!("  removal purpose: {p}\n"));
        }
        let op = e
            .get("open_operation_id")
            .and_then(serde_json::Value::as_str);
        if let Some(op) = op {
            out.push_str(&format!("  open operation: {op}\n"));
        }
        if state == "held" {
            let reason = e
                .get("hold")
                .and_then(|h| h.get("reason"))
                .and_then(serde_json::Value::as_str);
            match reason {
                Some(r) => out.push_str(&format!("  held: reason {r}\n")),
                None => out.push_str(
                    "  held: reason not reported by this runtime (inspect enrollments carries no hold reason)\n",
                ),
            }
            out.push_str("  next step:\n");
            for c in held_next(reason, &id, op) {
                out.push_str(&format!("    {c}\n"));
            }
        }
        if state == "outcome_unknown" || state == "remove_unknown" || state == "rollback_unknown" {
            out.push_str(&format!(
                "  next step: heimdall enroll reconcile {}\n",
                op.unwrap_or("<operation>")
            ));
        }
        if state == "abandoned" {
            out.push_str(
                "  abandoned: trust may remain on the destination (pending_until_line_removed)\n",
            );
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ca_key_is_cut_as_the_runtime_cuts_it() {
        let line = "cert-authority,principals=\"hm:dst:acct\" ssh-ed25519 AAAAkey heimdall:enr_1";
        assert_eq!(ca_key_of_line(line), "ssh-ed25519 AAAAkey");
        assert_eq!(ca_key_of_line(""), "");
    }

    #[test]
    fn only_removed_is_removed() {
        for s in EnrollmentState::ALL {
            let line = state_line("enr_x", s, Some(EnrollmentForm::System));
            if s != EnrollmentState::Removed {
                assert!(
                    !line.contains("absence verified"),
                    "{s:?} never claims an absence check: {line}"
                );
            }
        }
        assert!(
            state_line("e", EnrollmentState::ManualRemovalPending, None).contains("NOT removed")
        );
    }

    #[test]
    fn held_next_names_the_commands_per_reason() {
        let n = held_next(Some("host_key_changed"), "enr_1", None);
        assert!(n[0].contains("--approve-target-change"));
        let n = held_next(Some("lock_holder_unresolved"), "enr_1", Some("op_1"));
        assert!(n[1].contains("reconcile op_1 --after-manual-recovery"));
        assert_eq!(held_next(None, "e", None).len(), 4);
    }
}
