#!/usr/bin/env python3
"""Build tests/evidence/g04-exp-*.json records from one run of tests/native/g04/run_all.sh.

Usage: python3 tests/native/g04/make_records.py <RUN_STAMP> [--validate]

Reads tests/evidence/artifacts/g04/experiments/<RUN_STAMP>/{run.env,exit-codes.txt,
script-sha256.txt,fixture-versions.txt,fixture-*.log,<exp>.results.tsv,<exp>.log} and, if
present, review.json (written by the reviewing agent after reading the logs: per-case
"summary" text and optional "status"/"verdict" override with "status_reason").

Records follow the gate-probe convention in tests/evidence/README.md:
  status   = state of the evidence, not whether the hypothesis held:
             verified     the experiment ran to completion as designed (exit 0 or 1, no setup
                          failure, every validity precondition held) and its raw output is kept;
                          this holds even when the criterion failed
             in_progress  interrupted / setup failure / a validity precondition failed / no exit
                          row: the evidence is invalid or incomplete
  observed_result.verdict = pass | fail | inconclusive against the experiment's stated criterion
             (docs/research/g04-managed-credentials.md section 8.1): pass if every criterion
             CHECK passed and every criterion hypothesis was CONFIRMED; fail if any of them did
             not; inconclusive whenever status is not verified.
CHECK rows are classified per experiment as validity (preconditions that make the measurement
meaningful), info (recorded, not part of the criterion) or criterion (default). OBS rows are
hypotheses; only those listed as criterion affect the verdict, the rest are findings.
Only observations are written; nothing here is inferred output. --validate checks every written
record against tests/evidence/record.schema.json (needs the jsonschema package).
"""
import hashlib
import json
import os
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
G04 = os.path.join(REPO, "tests", "native", "g04")
DESIGN = "docs/research/g04-managed-credentials.md section 8.1"

# Each entry: script, results name, case_id, record file, requirement ids, acceptance refs,
# design row, stated criterion, validity CHECK names, info CHECK names, criterion OBS names,
# experiment-specific limitations.
EXPERIMENTS = [
    dict(script="e1_dedicated_agent", name="e1-dedicated-agent", case_id="G04-exp-dedicated-agent",
         record="g04-exp-e1-dedicated-agent.json", reqs=["R-CR-02", "R-CR-03"],
         acc=["A03 (substrate)", "A09 (substrate)"], design="E1",
         criterion="(a) the dedicated agent lists exactly K_env and its certificate; (b) fresh login rc 0 with a new Accepted line carrying the certificate ID; (c) the same with IdentityAgent=none rc 255; (d) only the temp socket is used; (e) after the ssh-add -t lifetime ssh-add -T and a fresh login both fail; (f) killing the exact agent PID removes process and socket. Fail: any deviation; any use of a non-temp socket.",
         validity={"E1-private-file-deleted"}, info=set(), crit_obs=set(),
         limits=["Agent lifetime measured with ssh-add -t on an awake, unlocked machine; the effect of sleep, screen lock, logout or reboot on the agent is not tested here (owner-run probes P1-P6).",
                 "Private key files were deleted with rm after ssh-add; no secure-erase claim is made (APFS/SSD)."]),
    dict(script="e2_cert_expiry", name="e2-cert-expiry", case_id="G04-exp-cert-expiry",
         record="g04-exp-e2-cert-expiry.json", reqs=["R-AU-05", "R-AU-08"],
         acc=["A23 (preliminary, new authentication only)"], design="E2",
         criterion="C1 before valid_before: rc 0. C1 after valid_before: rc 255 with an expiry reason in the server log. C2 (not yet valid) and C3 (expired): rc 255. The after-expiry rejection is the same with and without the agent still holding the certificate. Time from valid_before to first rejection <= 2 s + measured offset. Fail: any acceptance outside the window beyond the offset.",
         validity={"E2-agents-still-hold-certs"}, info={"E2-grace-removal"}, crit_obs=set(),
         limits=["Covers NEW authentication only. Existing connections and multiplexed sessions after expiry are covered by G09-prelim-mux-after-expiry.",
                 "Boundary resolution is limited by back-to-back login duration (tens of ms) and integer-second certificate validity; host and container share the Docker Desktop VM clock (offset measured, not independently skewed).",
                 "Skewed or rolled-back server clocks are not tested (G09 virtual-clock work)."]),
    dict(script="e3_principal_scope", name="e3-principal-scope", case_id="G04-exp-principal-scope",
         record="g04-exp-e3-principal-scope.json", reqs=["R-CR-07", "R-AU-08"],
         acc=["A10 (scope half, preliminary)"], design="E3",
         criterion="{p-host1}: ca1 ok, ca2 rc 255; {p-host2}: mirror; {p-host1,p-host2}: both ok, recorded as 'certificate usable on both', never as scoped; {cert} (the username): both rc 255 (principals file present); rogue CA and bare key: rc 255 on both. A rejected certificate counts only if the server evaluated it (Failed line with its ID), with the principal reason where a trusted CA signed it. Fail: any other outcome.",
         validity=set(), info=set(), crit_obs=set(),
         limits=["System-level trust only (TrustedUserCAKeys + AuthorizedPrincipalsFile, enrollment capability 3); account-level CA trust is G04-exp-account-ca-principals.",
                 "The broad two-principal certificate being accepted by both hosts is recorded as 'usable on both', never as scoped: per-destination scope exists only through the server-side principal map."]),
    dict(script="e4_account_ca_principals", name="e4-account-ca-principals", case_id="G04-exp-account-ca-principals",
         record="g04-exp-e4-account-ca-principals.json", reqs=["R-CR-05", "R-CR-06", "R-CR-07"],
         acc=["A09 (mechanics, preliminary)", "A10 (scope half, preliminary)"], design="E4",
         criterion="With cert-authority,principals=\"hm:fx-enroll:enroll\" <fixture CA> added by a preimage-checked, atomic, marker-tagged transaction: principal hm:fx-enroll:enroll rc 0; principal enroll (the username) rc 255 (principals= restricts); ops from our CA rc 255 (the seed's ops line trusts a different CA key; also checked before our line exists); without the line rc 255. Unrelated lines byte-identical; seed SHA-256 restored after removal by marker. Fail: any acceptance of enroll or ops; any change to unrelated bytes.",
         validity={"E4-preimage-is-seed", "E4-add-transaction"}, info=set(), crit_obs=set(),
         limits=["The add transaction is check-then-rename without a lock: a write landing between the remote digest check and the rename would be lost. That window was not exercised.",
                 "Interrupted mutation and lost responses (A09 outcome_unknown reconciliation) are not tested; fixture row 14 is not built.",
                 "Revocation lists (RevokedKeys/KRL) are sshd_config settings and are not available with account-level trust; not tested."]),
    dict(script="enroll_marker_key", name="enroll-marker-key", case_id="G04-exp-enroll-marker-key",
         record="g04-exp-enroll-marker-key.json", reqs=["R-CR-05", "R-CR-06"],
         acc=["A09 (mechanics, preliminary)"], design="enrollment mechanics (spec 7.5; supports E4/E6)",
         criterion="With fallback and connection reuse disabled and only the marker key offered: fresh authentication fails before enrollment, succeeds (exactly one new Accepted line with the marker fingerprint) after the marker line is added alongside existing access, and fails after removal; existing access survives; removal by marker preserves every unrelated byte and a concurrent administrator edit; seed restored. Fail: any deviation.",
         validity={"ENR-verification-config", "ENR-preimage-is-seed", "ENR-add-transaction", "ENR-concurrent-edit-applied"},
         info=set(), crit_obs=set(),
         limits=["The concurrent administrator edit was a plain append between enrollment and removal; it did not race the rename itself. The check-then-rename TOCTOU window is not exercised.",
                 "Interrupted mutation, lost responses and rotation are not tested.",
                 "Only the authorized_keys file at the path sshd is configured to read on this fixture was edited; discovery of the authoritative registry on real hosts is out of scope."]),
    dict(script="e5_issuer_separation", name="e5-issuer-separation", case_id="G04-exp-issuer-separation",
         record="g04-exp-e5-issuer-separation.json", reqs=["R-CR-04", "R-AU-07"],
         acc=["A10 (issuer half, preliminary)", "A28 (attenuation, preliminary)"], design="E5",
         criterion="(a) From the worker-only environment the CA is absent and signing through the worker socket fails. (b) The child certificate (principal subset, earlier valid_before) is refused on ca2 and, after its own expiry, on ca1 while the parent still works. (c) No CA private material in the worker/child path. Fail: CA reachable from the worker path; child broader or longer than its parent.",
         validity={"E5-issuer-holds-ca", "E5-issuer-signs-via-agent", "E5-child-cert-narrower"}, info=set(), crit_obs=set(),
         limits=["Issuer, worker and child are the same OS user. Separation is by agent endpoint only; a same-user process that knows the issuer socket path can obtain signatures (recorded as the E5-same-user-boundary finding). Stronger isolation needs a separate OS account/service or external issuer (spec 7.3).",
                 "The attenuation (child principals a subset, earlier valid_before) was chosen by the harness when it asked the issuer agent to sign; ssh-agent itself enforces no issuance policy. What was observed is that the issued certificates carry the narrower values and that the servers enforce them.",
                 "Scan for CA material covered the worker/child temp dirs, the worker/child agent processes' argv and environment (counts only, never printed) and the worker command environment, not process memory.",
                 "The fixture CA private key FILE (tests/fixtures/ssh/runtime/keys/user_ca, loaded into the issuer agent) stayed on disk and readable by the same OS user from the worker-only environment for the whole experiment (finding E5-ca-file-readable-by-same-user). 'No CA material in the worker path' therefore means: not in the worker/child files, agent argv/env or worker env, and not reachable through the worker agent endpoint. It is an environment and endpoint boundary only, not a file-access boundary."]),
    dict(script="e6_fresh_login_verification", name="e6-fresh-login-verification", case_id="G04-exp-fresh-login-verification",
         record="g04-exp-e6-fresh-login-verification.json", reqs=["R-CR-05"],
         acc=["A09 (verification step, preliminary)"], design="E6",
         criterion="With a live ControlMaster open, the verification command (ControlMaster=no, ControlPath=none, explicit identity/certificate/agent, publickey only, BatchMode) gives rc 0 and exactly one new Accepted line with the expected key ID; the negative control through the control socket gives rc 0 with no new Accepted line. Fail: verification succeeds without a new Accepted line, or the line carries another key ID.",
         validity={"E6-master-open"}, info={"E6-master-closed"}, crit_obs=set(),
         limits=["Freshness is attributed through sshd LogLevel VERBOSE lines (new TCP connection, Accepted publickey with the certificate key ID); a server without such logging needs another freshness signal."]),
    dict(script="e7_mux_after_expiry", name="e7-mux-after-expiry", case_id="G09-prelim-mux-after-expiry",
         record="g04-exp-g09-prelim-mux-after-expiry.json", reqs=["R-AU-05", "R-AU-08"],
         acc=["A23 (preliminary)"], design="E7 phases 1-4",
         criterion="Verdict criterion H2 (control connections opened AFTER the stop only): after ssh -O stop, (a) -O check fails, (b) a new client using the old ControlPath makes a new, rejected connection (rc 255) and a client that cannot authenticate is not admitted, and (c) the already-open session S1 continues. Fail: H2 refuted (any admission of a new client after stop, or S1 killed). Scope note (M00-review-g04): this criterion does not cover control connections the master accepted before the stop; those are G09-prelim-mux-preconnected-after-stop (verdict fail: still admitted), so a pass here does NOT show that -O stop stops admissions. H1 (whether certificate expiry alone stops new multiplexed sessions), the master's exit after its last session, and -O exit effects are recorded as findings; they do not by themselves pass or fail the recipe.",
         validity={"E7-master-authenticated", "E7-P1-mux-before-expiry", "E7-P2a-fresh-login-rejected"},
         info={"E7-P2c-S1-alive-after-expiry"},
         crit_obs={"H2a-check-fails-after-stop", "H2b-new-client-falls-back-to-fresh-auth", "H2b2-no-admission-via-master-after-stop", "H2c-open-session-continues-after-stop"},
         limits=["One client/server version pair; masters started with -N -f and ControlPersist=10m; sessions without a tty; only Heimdall-like owned masters, no unmanaged connections.",
                 "Detached remote processes (nohup/setsid) were not tested; the remote-process listing only shows which processes of the account remained after -O exit.",
                 "Preliminary G09 evidence only: it does not select the ordinary/strict policy (spec P06) and does not cover clock skew, sleep across the deadline, or revocation.",
                 "H2 exercises only clients that connect to the control path after -O stop. A control connection accepted before the stop was still granted sessions and forwards after it (G09-prelim-mux-preconnected-after-stop). H2d (master exits after its last session) held because no other control connection was open in this run; with an idle pre-accepted control connection the stopped master stays up."]),
    dict(script="e7_mux_preconnected", name="e7-mux-preconnected", case_id="G09-prelim-mux-preconnected-after-stop",
         record="g04-exp-g09-prelim-mux-preconnected-after-stop.json", reqs=["R-AU-05", "R-AU-08"],
         acc=["A23 (preliminary)"], design="E7 phase 5 (pre-accepted control connections; adopted from the M00-review-g04 probe)",
         extra_files=["e7_mux_preconnected.py"],
         criterion="After ssh -O stop returned rc 0 (control socket removed, -O check failing), every request on a mux control connection the master accepted BEFORE the stop is refused or the connection is closed: MUX_C_NEW_SESSION on ca1 after certificate expiry at stop+2 s (H2e) and on a second connection idle until stop+15 s (H2e2); MUX_C_OPEN_FWD local (H2f) and remote (H2g) and MUX_C_NEW_STDIO_FWD (H2h) on bastion. Pass: all refused. Fail: any granted (session opened and the remote command ran / forward replied OK and carried traffic). Validity: master authenticated once; the raw client opens a session and each forward type works before the stop; fresh login after expiry refused; -O stop took effect; a new client after stop refused. Findings (not criterion): the stopped master's lifetime with an idle pre-accepted connection (H2d-held, H2d-exit); -O exit (H3c) and exact-PID SIGTERM (H3d) close pre-accepted connections.",
         validity={"E7P-A-master-authenticated", "E7P-A-raw-client-session-before-stop", "E7P-A-fresh-login-rejected-after-expiry", "E7P-A-stop-effective",
                   "E7P-B-master-authenticated", "E7P-B-local-fwd-before-stop", "E7P-B-remote-fwd-before-stop", "E7P-B-stdio-fwd-before-stop", "E7P-B-stop-effective"},
         info={"E7P-A-new-client-after-stop-refused"},
         crit_obs={"H2e-preconnected-session-refused-after-stop", "H2e2-preconnected-session-refused-late", "H2f-preconnected-local-fwd-refused-after-stop",
                   "H2g-preconnected-remote-fwd-refused-after-stop", "H2h-preconnected-stdio-fwd-refused-after-stop"},
         limits=["The pre-accepted control connections are made by a raw mux protocol v4 client in the harness (Python, fd passing), not by /usr/bin/ssh. Any same-user process that connected to the control socket before the stop can do the same; an ssh client that connected before the stop holds such a connection only while it is starting or running its own session.",
                 "Phase A (session after certificate expiry) runs against ca1 (AllowTcpForwarding no); forwards are tested against the bastion fixture (AllowTcpForwarding yes, PermitOpen hm-m00t03-target:22) with the fixture's bastion key, without certificate expiry. Remote-forward admission is shown by the remote listener accepting a TCP connection inside the bastion container; the forwarded connection itself was not carried to a client-side service.",
                 "MUX_C_PROXY, dynamic (SOCKS) forwards and streamlocal forwards were not tested; by the same source reasoning they are expected [I] to behave alike.",
                 "One client version (Apple OpenSSH_10.3p1); source reasoning is from openssh-portable mux.c @87f0cd1. Preliminary G09 evidence; does not select the ordinary/strict policy (spec P06)."]),
    dict(script="e7_mux_stop_race", name="e7-mux-stop-race", case_id="G09-prelim-mux-stop-race",
         record="g04-exp-g09-prelim-mux-stop-race.json", reqs=["R-AU-05"],
         acc=["A23 (preliminary)"], design="E7 race",
         criterion="Race of a client connect against ssh -O stop with randomized start delays (client 0-60 ms, stop 0-40 ms by default; see run knobs) (client cannot authenticate, so rc 0 means admitted through the master): 0 admissions of clients that started after the -O stop call had returned (MUX_S_OK received). Admissions of clients that overlapped the stop call cannot be ordered from the host and are reported separately. Validity precondition: at least 5 clients started after the stop call returned.",
         validity={"E7R-harness", "E7R-post-stop-clients-exercised"}, info=set(), crit_obs={"E7R-no-admission-after-stop-returned"},
         limits=["Host-side millisecond timestamps include process start overhead; the instant the -O stop client receives MUX_S_OK is not observable from outside, so admissions of clients that started while the stop call was in flight are reported separately and not counted as violations.",
                 "Small sample (N=50 by default), single host, masters without other sessions; not a proof of absence of a race, only of none observed.",
                 "Classification is by client process start time. A client whose control connection the master accepted before the listener closed is a pre-accepted connection, and such connections are admitted after MUX_S_OK (G09-prelim-mux-preconnected-after-stop); admissions classed started_during_stop are consistent with that. The race criterion therefore cannot show that -O stop stops admissions; it shows only that clients that started after stop returned found no listener."]),
]


def common_limits(facts, fx):
    host_ssh = facts.get("host_ssh") or fx.get("host_ssh") or "unknown"
    sshd = fx.get("sshd_version_banner") or facts.get("container_sshd") or "unknown"
    return [
        f"OpenSSH mechanism evidence only: host client /usr/bin/ssh ({host_ssh}, macOS) against sshd ({sshd}) in disposable Docker fixture containers. No Heimdall code exists or ran; this is not evidence of Heimdall behavior.",
        "Not desktop-lock, sleep, logout, reboot or secure-store evidence: the dedicated agents are plain ssh-agent processes in an unlocked session started by the harness. Lock continuity remains open (owner-run probes).",
        "Single machine: macOS 27.0 arm64 with Docker Desktop (linux VM). No native Windows/WSL or Linux-host evidence. The openssh-server package version is observed, not pinned (apt floats at image build).",
        "Fixture sshd sets PerSourcePenalties no, unlike the OpenSSH 10 default.",
        "Requirement IDs are listed for traceability; this record is not by itself evidence that any product requirement is met (tests/evidence/README.md).",
        "Independent review M00-review-g04 (tests/evidence/artifacts/m00-wf2/review-g04.json) re-ran the earlier version of these experiments from scratch and refuted the earlier '-O stop: admissions stopped' conclusion; this record comes from the corrected harness (task M00-T04-G04-fix). The corrections themselves have not been independently re-reviewed.",
    ]


def read_kv(path):
    d = {}
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                d[k] = v
    return d


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def parse_results(path):
    checks, obs, facts, cleanup, exitrow, setup = [], [], {}, [], None, []
    if not os.path.exists(path):
        return checks, obs, facts, cleanup, exitrow, ["results file missing"]
    for line in open(path, encoding="utf-8"):
        p = line.rstrip("\n").split("\t")
        if p[0] == "CHECK" and len(p) >= 5:
            checks.append({"name": p[1], "expected": p[2], "observed": p[3], "result": p[4]})
        elif p[0] == "OBS" and len(p) >= 5:
            obs.append({"name": p[1], "hypothesis": p[2], "observed": p[3], "result": p[4]})
        elif p[0] == "FACT" and len(p) >= 3:
            facts[p[1]] = p[2]
        elif p[0] == "CLEANUP":
            cleanup.append(" ".join(p[1:]))
        elif p[0] == "EXIT":
            exitrow = p[1:]
        elif p[0] == "SETUP_FAILURE":
            setup.append(p[1] if len(p) > 1 else "")
    return checks, obs, facts, cleanup, exitrow, setup


def first_ts(logpath):
    if os.path.exists(logpath):
        for line in open(logpath, encoding="utf-8"):
            if line.startswith("[") and "]" in line:
                return line[1:line.index("]")].replace("Z", "+00:00")
    return None


def classify(e, rc, checks, obs, exitrow, setup):
    """Return (status, verdict, reason, per-row roles)."""
    for c in checks:
        c["role"] = "validity" if c["name"] in e["validity"] else ("info" if c["name"] in e["info"] else "criterion")
    for o in obs:
        o["role"] = "criterion" if o["name"] in e["crit_obs"] else "finding"
    missing_obs = sorted(e["crit_obs"] - {o["name"] for o in obs})
    missing_validity = sorted(e["validity"] - {c["name"] for c in checks})
    bad_validity = [c["name"] for c in checks if c["role"] == "validity" and c["result"] != "PASS"]
    if rc not in (0, 1) or exitrow is None or setup:
        return "in_progress", "inconclusive", f"experiment did not run to completion (exit {rc}; setup failures: {setup or 'none'})"
    if missing_validity or missing_obs:
        return "in_progress", "inconclusive", f"expected rows missing: validity {missing_validity}, criterion hypotheses {missing_obs}"
    if bad_validity:
        return "in_progress", "inconclusive", f"validity precondition(s) did not hold: {bad_validity}; the measurement is not meaningful"
    crit_fail = [c["name"] for c in checks if c["role"] == "criterion" and c["result"] != "PASS"]
    crit_fail += [o["name"] for o in obs if o["role"] == "criterion" and o["result"] != "CONFIRMED"]
    ncrit = sum(1 for c in checks if c["role"] == "criterion") + len(e["crit_obs"])
    if ncrit == 0:
        return "in_progress", "inconclusive", "no criterion rows"
    if crit_fail:
        return "verified", "fail", f"ran as designed; criterion rows not satisfied: {crit_fail}"
    return "verified", "pass", "ran as designed; every criterion row satisfied"


def auto_summary(e, verdict, checks, obs):
    nc = [c for c in checks if c["role"] == "criterion"]
    parts = [f"verdict {verdict} against the stated criterion; criterion checks passed {sum(1 for c in nc if c['result'] == 'PASS')}/{len(nc)}"]
    for o in obs:
        parts.append(f"{o['name']} {o['result']} ({o['observed']})")
    return "; ".join(parts)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    validate = "--validate" in sys.argv[1:]
    if len(args) != 1:
        print(__doc__)
        return 2
    stamp = args[0]
    rel_out = f"tests/evidence/artifacts/g04/experiments/{stamp}"
    out = os.path.join(REPO, rel_out)
    run = read_kv(os.path.join(out, "run.env"))
    fx = read_kv(os.path.join(out, "fixture-versions.txt"))
    codes = {}
    for line in open(os.path.join(out, "exit-codes.txt"), encoding="utf-8"):
        if line.strip():
            s, c = line.split()
            codes[s] = int(c)
    review = {}
    rp = os.path.join(out, "review.json")
    if os.path.exists(rp):
        review = json.load(open(rp, encoding="utf-8"))
    lib_sha = sha256(os.path.join(G04, "lib.sh"))
    lifecycle = sorted(f for f in os.listdir(out) if f.startswith("fixture-") and f.endswith(".log"))
    up_log = os.path.join(out, "fixture-up.log")
    build_cached = os.path.exists(up_log) and "CACHED" in open(up_log, encoding="utf-8").read()
    written, paths = [], []
    for e in EXPERIMENTS:
        script, name = e["script"], e["name"]
        if script not in codes:
            continue
        rc = codes[script]
        checks, obs, facts, cleanup, exitrow, setup = parse_results(os.path.join(out, f"{name}.results.tsv"))
        status, verdict, reason = classify(e, rc, checks, obs, exitrow, setup)
        rv = review.get(e["case_id"], {})
        if rv.get("status"):
            status = rv["status"]
        if rv.get("verdict"):
            verdict = rv["verdict"]
        if rv.get("status_reason"):
            reason = rv["status_reason"]
        bad_tokens = ("still_running", "socket_still_present", "still_present", "not_signalled")
        unclean = [c for c in cleanup if any(w in c for w in bad_tokens)]
        if exitrow is not None and not any(c.startswith("tempdir") for c in cleanup):
            unclean.append("no tempdir cleanup row")
        extras = sorted(f for f in os.listdir(out) if f.startswith(name + ".") and f not in (f"{name}.log", f"{name}.results.tsv"))
        npass = sum(1 for c in checks if c["result"] == "PASS")
        limits = common_limits(facts, fx) + e["limits"]
        if unclean:
            limits.append(f"Cleanup rows not confirming removal: {unclean}")
        rec = {
            "case_id": e["case_id"],
            "status": status,
            "status_reason": reason,
            "requirement_ids": e["reqs"],
            "acceptance_refs": e["acc"],
            "design_ref": f"{DESIGN} {e['design']}",
            "build_commit": run.get("build_commit"),
            "artifact_digest": f"tests/native/g04/{script}.sh sha256 {sha256(os.path.join(G04, script + '.sh'))}; " + "".join(f"tests/native/g04/{x} sha256 {sha256(os.path.join(G04, x))}; " for x in e.get("extra_files", [])) + f"tests/native/g04/lib.sh sha256 {lib_sha} (working tree, uncommitted on top of build_commit; digests of all scripts as run are in {rel_out}/script-sha256.txt); record generated by tests/native/g04/make_records.py sha256 {sha256(os.path.abspath(__file__))}",
            "environment": {
                "host": "macOS 27.0 arm64",
                "docker": f"Docker Desktop, Engine {facts.get('docker_server') or fx.get('docker_server', 'unknown')} (linux VM)",
                "fixture": "tests/fixtures/ssh (M00-T03): hm-m00t03-ca1/ca2 (TrustedUserCAKeys, principals p-host1/p-host2, account cert), hm-m00t03-enroll (account-owned authorized_keys), loopback-published ports only; brought up fresh for this run",
                "fixture_image": f"heimdall-m00-t03-sshd:local {fx.get('fixture_image_id', '')} on {fx.get('base_image', 'unknown')}".replace("  ", " ")
                + ("; image layers reused from the Docker build cache (fixture-up.log shows CACHED), while keys, CA, host keys and containers were generated fresh by up.sh" if build_cached else ""),
                "clock": facts.get("clock_ca1", "not measured"),
                "ssh_auth_sock_in_harness": facts.get("ssh_auth_sock_in_harness", "not recorded"),
            },
            "provider_versions": [
                {"name": "ssh client (host /usr/bin/ssh)", "version": facts.get("host_ssh", "not recorded")},
                {"name": "openssh-server (container package)", "version": facts.get("container_sshd") or fx.get("openssh_server_pkg", "not recorded")},
                {"name": "sshd banner (container)", "version": fx.get("sshd_version_banner", "not recorded")},
                {"name": "docker engine", "version": facts.get("docker_server", "not recorded")},
            ],
            "started_at": first_ts(os.path.join(out, f"{name}.log")),
            "commands_or_harness": [
                f"tests/fixtures/ssh/down.sh then tests/fixtures/ssh/up.sh (fresh fixture material; logs {rel_out}/fixture-*.log)",
                f"G04_RUN_STAMP={stamp} tests/native/g04/run_all.sh -> tests/native/g04/{script}.sh exit {rc} (real exit code from {rel_out}/exit-codes.txt)",
                f"run knobs: {run.get('knobs', 'defaults')}",
                "all ssh calls: /usr/bin/ssh -F <generated per-experiment config> (StrictHostKeyChecking yes, fixture known_hosts, GlobalKnownHostsFile /dev/null, IdentitiesOnly yes, IdentityAgent = dedicated agent or none, ControlMaster no / ControlPath none unless the step is about multiplexing); SSH_AUTH_SOCK unset; never ~/.ssh or the owner's agent",
                f"tests/fixtures/ssh/down.sh after the run (log {rel_out}/fixture-down-post.log)",
                f"python3 tests/native/g04/make_records.py {stamp} --validate",
            ],
            "observed_result": {
                "verdict": verdict,
                "criterion": e["criterion"],
                "summary": rv.get("summary") or auto_summary(e, verdict, checks, obs),
                "exit_code": rc,
                "checks_passed": f"{npass}/{len(checks)}",
                "checks": checks,
                "hypotheses": obs,
                "facts": facts,
                "cleanup": cleanup,
                "setup_failures": setup,
            },
            "evidence_paths": [f"{rel_out}/{name}.log", f"{rel_out}/{name}.results.tsv"]
            + [f"{rel_out}/{x}" for x in extras]
            + [f"{rel_out}/{script}.stdout.txt", f"{rel_out}/exit-codes.txt", f"{rel_out}/run.env",
               f"{rel_out}/script-sha256.txt", f"{rel_out}/fixture-versions.txt"]
            + [f"{rel_out}/{f}" for f in lifecycle]
            + ([f"{rel_out}/fresh_run.stdout.txt"] if os.path.exists(os.path.join(out, "fresh_run.stdout.txt")) else [])
            + [f"tests/native/g04/{script}.sh"] + [f"tests/native/g04/{x}" for x in e.get("extra_files", [])] + ["tests/native/g04/lib.sh", "tests/native/g04/README.md"],
            "limitations": limits,
            "blocked_on": None,
        }
        path = os.path.join(REPO, "tests", "evidence", e["record"])
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=2, ensure_ascii=False)
            f.write("\n")
        paths.append(path)
        written.append((e["record"], status, verdict, rc, f"{npass}/{len(checks)}", len(obs)))
    for w in written:
        print("wrote tests/evidence/%s status=%s verdict=%s exit=%s checks=%s hypotheses=%s" % w)
    if validate:
        import jsonschema  # noqa: E402  (only needed for --validate)
        schema = json.load(open(os.path.join(REPO, "tests", "evidence", "record.schema.json"), encoding="utf-8"))
        bad = 0
        for p in paths:
            rec = json.load(open(p, encoding="utf-8"))
            errs = list(jsonschema.Draft202012Validator(schema).iter_errors(rec))
            if rec.get("observed_result") is not None and rec["observed_result"].get("verdict") not in ("pass", "fail", "inconclusive"):
                errs.append("observed_result.verdict missing or not pass|fail|inconclusive (gate-probe convention)")
            print("schema %s: %s" % (os.path.relpath(p, REPO), "valid" if not errs else "INVALID " + "; ".join(str(x) for x in errs)))
            bad += bool(errs)
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
