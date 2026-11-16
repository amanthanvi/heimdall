#!/usr/bin/env python3
"""U0b spike driver: measure ssh / git-over-ssh patience for a delayed
REQUEST_IDENTITIES answer. Everything lives in a fresh scratch dir that is
deleted at the end. Usage: spike_driver.py --platform NAME --out results.json
"""
import argparse, concurrent.futures as cf, json, os, re, secrets, shlex, shutil
import signal, socket, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
DELAYS = [0, 0.5, 1, 2, 5, 10, 30]
USER = os.environ.get("USER") or subprocess.check_output(["id", "-un"], text=True).strip()


def sh(cmd, **kw):
    kw.setdefault("text", True)
    kw.setdefault("capture_output", True)
    return subprocess.run(cmd, **kw)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--smoke", action="store_true", help="only D=0,1; skip 65/125")
    a = ap.parse_args()

    root = tempfile.mkdtemp(prefix="hm-w0-spike.", dir="/tmp")
    data = os.path.join(root, "data")
    os.makedirs(data)
    sock_dir = os.path.join(root, "s")
    os.makedirs(sock_dir)
    env = {k: v for k, v in os.environ.items()
           if not (k.startswith("GIT_") or k in ("SSH_AUTH_SOCK", "SSH_AGENT_PID"))}
    pids = {}      # name -> exact pid we started
    procs = []
    result = {"platform": a.platform, "scratch_root_name": os.path.basename(root)}
    try:
        canary = "HM-SPIKE-CWD-" + secrets.token_hex(8)
        remote_name = "hm-spike-remote-" + secrets.token_hex(4)
        work = os.path.join(data, "work", canary)
        bare = os.path.join(data, remote_name, "repo.git")
        os.makedirs(work)
        os.makedirs(os.path.dirname(bare))
        sh(["git", "init", "-q", work], env=env, check=True)
        sh(["git", "init", "-q", "--bare", bare], env=env, check=True)
        needles = ["--needle", "canary=" + canary, "--needle", "cwd=" + work,
                   "--needle", "repo_name=" + os.path.basename(work),
                   "--needle", "remote_repo=" + remote_name,
                   "--needle", "scratch_root=" + root]

        # versions
        ssh_v = sh(["ssh", "-V"]).stderr.strip()
        result["versions"] = {
            "ssh_V": ssh_v, "git_version": sh(["git", "--version"]).stdout.strip(),
            "uname_a": sh(["uname", "-a"]).stdout.strip(),
            "python": sys.version.split()[0],
            "ssh_path": shutil.which("ssh"), "git_path": shutil.which("git")}

        # keys
        ck, hk = os.path.join(data, "client_key"), os.path.join(data, "host_key")
        for k in (ck, hk):
            sh(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", k, "-C", "hm-spike"], check=True)
        shutil.copy(ck + ".pub", os.path.join(data, "authorized_keys"))
        hostpub = open(hk + ".pub").read().split()[:2]

        # disposable agent
        agent_sock = os.path.join(sock_dir, "a.sock")
        out = sh(["ssh-agent", "-a", agent_sock], env=env, check=True).stdout
        agent_pid = int(re.search(r"SSH_AGENT_PID=(\d+)", out).group(1))
        pids["ssh-agent"] = agent_pid
        aenv = dict(env, SSH_AUTH_SOCK=agent_sock)
        sh(["ssh-add", ck], env=aenv, check=True)
        result["agent_pid"] = agent_pid

        # two sshds: LoginGraceTime 120 (default) and 0 (unlimited)
        servers = {}
        for grace in (120, 0):
            port = free_port()
            cfg = os.path.join(data, "sshd_config_%d" % grace)
            open(cfg, "w").write("\n".join([
                "ListenAddress 127.0.0.1", "Port %d" % port, "HostKey " + hk,
                "AuthorizedKeysFile " + os.path.join(data, "authorized_keys"),
                "PubkeyAuthentication yes", "PasswordAuthentication no",
                "KbdInteractiveAuthentication no", "UsePAM no", "StrictModes no",
                "PidFile " + os.path.join(data, "sshd_%d.pid" % grace),
                "LoginGraceTime %d" % grace, "MaxStartups 100:30:200", ""]))
            T = sh(["/usr/sbin/sshd", "-T", "-f", cfg]).stdout
            if re.search(r"^PerSourcePenalties ", T, re.M | re.I):  # OpenSSH >= 9.8 only
                open(cfg, "a").write("PerSourcePenalties no\n")
                T = sh(["/usr/sbin/sshd", "-T", "-f", cfg]).stdout
            eff = re.search(r"^logingracetime (\d+)", T, re.M | re.I).group(1)
            lf = open(os.path.join(data, "sshd_%d.log" % grace), "w")
            p = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", cfg], env=env,
                                 stdout=lf, stderr=lf)
            procs.append(p)
            pids["sshd_grace_%d" % grace] = p.pid
            kh = os.path.join(data, "known_hosts_%d" % grace)
            open(kh, "w").write("[127.0.0.1]:%d %s %s\n" % (port, hostpub[0], hostpub[1]))
            servers[grace] = dict(port=port, kh=kh, effective_login_grace_time=int(eff))
            for _ in range(50):
                try:
                    socket.create_connection(("127.0.0.1", port), 1).close()
                    break
                except OSError:
                    time.sleep(0.1)
        result["servers"] = {str(g): dict(effective_login_grace_time=s["effective_login_grace_time"],
                                          listen="127.0.0.1")
                             for g, s in servers.items()}
        result["pids_started"] = dict(pids)

        def one(client, D, grace):
            srv = servers[grace]
            tag = "%s_%s_%s" % (client, str(D).replace(".", "p"), grace)
            psock = os.path.join(sock_dir, tag[:20] + ".sock")
            plog = os.path.join(data, "proxy_%s.jsonl" % tag)
            proxy = subprocess.Popen(
                [sys.executable, "-I", os.path.join(HERE, "spike_agent_proxy.py"),
                 "--listen", psock, "--upstream", agent_sock, "--delay", str(D),
                 "--log", plog] + needles, env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    if os.path.exists(psock):
                        break
                    time.sleep(0.05)
                opts = ["ssh", "-vvv", "-F", "/dev/null", "-o", "IdentityAgent=" + psock,
                        "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
                        "-o", "StrictHostKeyChecking=yes",
                        "-o", "UserKnownHostsFile=" + srv["kh"],
                        "-o", "GlobalKnownHostsFile=/dev/null",
                        # explicit nonexistent IdentityFile: stops ssh from probing default ~/.ssh keys
                        "-o", "IdentityFile=" + os.path.join(data, "no-such-identity")]
                if client == "ssh":
                    cmd = opts + ["-p", str(srv["port"]), "%s@127.0.0.1" % USER, "true"]
                    cenv = env
                else:
                    cmd = ["git", "ls-remote",
                           "ssh://%s@127.0.0.1:%d%s" % (USER, srv["port"], bare)]
                    cenv = dict(env, GIT_SSH_COMMAND=shlex.join(opts),
                                GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1",
                                GIT_TERMINAL_PROMPT="0")
                t = time.monotonic()
                timed_out = False
                cp = subprocess.Popen(cmd, cwd=work, env=cenv, text=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    so, se = cp.communicate(timeout=D + 150)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    cp.kill()
                    so, se = cp.communicate()
                el = round(time.monotonic() - t, 3)
                time.sleep(0.2)
                ev = [json.loads(l) for l in open(plog)]
                reqs = [e for e in ev if e["ev"] == "req"]
                needle_hits = sorted({k for r in reqs for k, v in r.items()
                                      if k.startswith("has_") and v})
                conns = {}
                for r in reqs:
                    conns.setdefault(r["conn"], []).append(
                        "%d%s" % (r["type"], ":" + r["ext"] if r["ext"] else ""))
                resp11 = [e for e in ev if e["ev"] == "resp" and e.get("delayed_s") is not None
                          and any(r["conn"] == e["conn"] and r["seq"] == e["seq"] and r["type"] == 11
                                  for r in reqs)]
                closed = [e for e in ev if e["ev"] == "client_closed_during_delay"]
                # client acted on the answer iff it sent a later request on that connection
                acted = any("11" in seq and "13" in seq and seq.index("13") > seq.index("11")
                            for seq in conns.values())
                dbg = [l for l in se.splitlines()
                       if re.search(r"agent returned|ssh_fetch_identitylist|get_agent_identities|agent contains|agent offers|identity from agent|session-bind|Offering public|Server accepts key|Authentication succeeded|Permission denied|Will attempt key|Connection (closed|reset)|Timeout", l, re.I)][:40]
                errs = [l for l in se.splitlines() if not l.startswith("debug")][-6:]
                return dict(
                    client=client, delay_s=D, login_grace_time=srv["effective_login_grace_time"],
                    exit_code=cp.returncode, elapsed_s=el, timed_out=timed_out,
                    success=(cp.returncode == 0),
                    answer_delivered=any(e.get("delivered") for e in resp11),
                    client_closed_during_delay=bool(closed),
                    client_closed_after_s=(closed[0]["waited_s"] if closed else None),
                    client_sent_more_after_answer=acted,
                    needle_hits=needle_hits,
                    message_sequences_per_connection=conns,
                    session_bind_after_request_identities=any(
                        "27:session-bind@openssh.com" in s and "11" in s and
                        s.index("27:session-bind@openssh.com") > s.index("11") for s in conns.values()),
                    session_bind_seen=any("27:session-bind@openssh.com" in s for s in conns.values()),
                    messages=[{k: r[k] for k in r if k != "ev"} for r in reqs],
                    stdout_lines=so.count("\n"), stderr_error_lines=errs, debug_agent_lines=dbg)
            finally:
                proxy.terminate()
                proxy.wait()

        jobs = [("ssh", 125, 120), ("git", 125, 120), ("ssh", 65, 0), ("git", 65, 0)]
        jobs += [(c, d, 120) for d in DELAYS for c in ("ssh", "git")]
        if a.smoke:
            jobs = [(c, d, 120) for d in (0, 1) for c in ("ssh", "git")]
        def probe():
            """Raw TCP client that never authenticates: how long does sshd (grace 120) keep it?"""
            c = socket.create_connection(("127.0.0.1", servers[120]["port"]))
            t = time.monotonic()
            c.settimeout(200)
            try:
                while c.recv(4096):
                    pass
            except OSError as e:
                return dict(closed_by="error " + repr(e), elapsed_s=round(time.monotonic() - t, 3))
            return dict(closed_by="server EOF", elapsed_s=round(time.monotonic() - t, 3))

        with cf.ThreadPoolExecutor(a.workers + 1) as ex:
            pf = None if a.smoke else ex.submit(probe)
            runs = list(ex.map(lambda j: one(*j), jobs))
            if pf:
                result["server_grace_probe_unauthenticated_connection"] = pf.result()
        runs.sort(key=lambda r: (r["client"], r["delay_s"]))
        result["runs"] = runs
        summ = {}
        for c in ("ssh", "git"):
            ok = [r["delay_s"] for r in runs if r["client"] == c and r["success"]]
            bad = [r for r in runs if r["client"] == c and not r["success"]]
            summ[c] = dict(max_delay_succeeded_s=max(ok) if ok else None,
                           failures=[dict(delay_s=r["delay_s"], exit_code=r["exit_code"],
                                          elapsed_s=r["elapsed_s"],
                                          login_grace_time=r["login_grace_time"]) for r in bad])
        summ["any_needle_hit_in_any_message"] = sorted({h for r in runs for h in r["needle_hits"]})
        summ["total_agent_messages_logged"] = sum(len(r["messages"]) for r in runs)
        summ["message_types_seen"] = sorted({m["type_name"] + (":" + m["ext"] if m["ext"] else "")
                                             for r in runs for m in r["messages"]})
        for g in (120, 0):
            lg = open(os.path.join(data, "sshd_%d.log" % g)).read().splitlines()
            summ["sshd_log_grace_%d" % g] = dict(
                timeout_before_authentication_lines=sum("Timeout before authentication" in l for l in lg),
                accepted_publickey_lines=sum(l.startswith("Accepted publickey") for l in lg))
        result["summary"] = summ
        result["note"] = ("client run with extra options -vvv, GlobalKnownHostsFile=/dev/null and a "
                          "nonexistent IdentityFile so default ~/.ssh keys are never probed; "
                          "runs executed with up to %d in parallel against MaxStartups 100:30:200" % a.workers)
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(10)
                except subprocess.TimeoutExpired:
                    p.kill()
        ap_ = pids.get("ssh-agent")
        if ap_:
            comm = sh(["ps", "-o", "comm=", "-p", str(ap_)]).stdout.strip()
            if comm.endswith("ssh-agent"):
                os.kill(ap_, signal.SIGTERM)
        time.sleep(0.5)
        shutil.rmtree(root, ignore_errors=True)
        result["scratch_removed"] = not os.path.exists(root)
        with open(a.out, "w") as f:
            json.dump(result, f, indent=1)
    print("results:", a.out, "scratch_removed:", result["scratch_removed"])


if __name__ == "__main__":
    main()
