import json, hashlib, sys
W = 'tests/evidence/artifacts/g02-r4/x1/windows-96'
RUNS = ['s96-ps51-a', 's96-ps7-a', 's96-ps51-b']
docs = {r: json.load(open(f'{W}/{r}/results.json', encoding='utf-8-sig')) for r in RUNS}
def sha(p): return hashlib.sha256(open(p, 'rb').read()).hexdigest()
base = docs['s96-ps51-a']
ident = all({(x['candidate'], x['id']): x['verdict'] for x in docs[r]['rows']} == {(x['candidate'], x['id']): x['verdict'] for x in base['rows']} for r in RUNS)
assert ident
envf = [x for x in base['rows'] if x['id'] == 'env.facts'][0]['observed']
host_rows = [{k: x[k] for k in ('id', 'verdict', 'gating', 'criterion', 'observed')} for x in base['rows'] if x['candidate'] == 'host']
for h in host_rows:
    if h['id'] == 'env.facts': h.pop('criterion')
meta = {'go': ('38b6b72', 'ca5145d16414125d54dbeb6c9bc6e10a8d18a9b38345b0b80a07fbfe906504ed'),
        'rust': ('d8f0cbe', 'dde9662f0630bf555df1a94c319e6c463d9e0e81b29b059136ea181234071ccd')}
supp = {p: sha(p) for p in ['tests/native/windows-g02/G02X1Native.cs', 'tests/native/windows-g02/Send-ConsoleCtrl.ps1',
    'tests/native/windows-g02/StallPipe.ps1', 'tests/native/windows-g02/expected-homelab.json', 'tests/native/windows-g02/argvdump/main.go',
    'tests/native/windows/G03Common.psm1', 'tests/native/windows/InstrumentedAgent.ps1', 'tests/native/windows/fixtures/quoting-cases.json',
    'schemas/g02/result.schema.json']}
for c in ('go', 'rust'):
    prev = json.load(open(f'tests/evidence/artifacts/g02-r4/x1/prev-records/g02-{c}-x1-windows.pre-9.6.json'))
    rows = [{k: x[k] for k in ('id', 'verdict', 'gating', 'criterion', 'observed')} for x in base['rows'] if x['candidate'] == c]
    summ = dict(base['summary'][c])
    summ['non_gating_not_pass'] = [x['id'] for x in rows if not x['gating'] and x['verdict'] not in ('pass', 'info')]
    summ['runs'] = {r: {'powershell': docs[r]['powershell'], 'summary': docs[r]['summary'][c]} for r in RUNS}
    summ['verdicts_identical_across_runs'] = ident
    verdict = 'pass' if not summ['gating_not_pass'] and all(h['verdict'] in ('pass', 'info') for h in host_rows) else 'fail'
    if c == 'go':
        findings = [
            "run.batch_target.* (4 rows, section 9.6): Go fails all four. Path without a space: 6 of 16 arguments reach the batch file exactly; 8 run an injected command (`&`, `|`, `>`, `<`+`&`, `^^&`, `%VAR%` twice, `\" & ...`); `a<file` and `a^b` arrive changed. Path with a space: only `plain` arrives; 8 inject, 5 never start the batch file (cmd.exe splits the path; exit 1, not 127), 2 arrive changed. Go passes .bat/.cmd to CreateProcess, which runs `cmd.exe /c` on Go's CommandLineToArgvW-style quoting (inference from the outcomes and the Go source; not instrumented).",
            "Every Go batch run exits 1, including the exact ones. run.batch_control shows the same exit 1 for `cmd.exe /c` WITHOUT /d (the owner's cmd.exe AutoRun is configured and writes 94 bytes to stderr) and exit 0 with /d, so the exit code is attributed to AutoRun, not to Go; batch-row exit codes are recorded, not gated.",
            "K14 (section 9.6): profile show and tui exit 2 within ~25 ms for a named pipe, NUL and a directory. Go opens the pipe once (pipe_connects 1, final count) before refusing.",
            "agent list --socket (section 9.6): a regular file, a directory and a non-existent path all give exit 5 AGENT_UNAVAILABLE ('connect failed') with nothing modified or created."]
    else:
        findings = [
            "profile.named_pipe_as_file and tui.named_pipe_as_file (K14, section 9.6): Rust does not exit within 10 s on a named pipe whose server never answers; the script killed it. It opened the pipe (pipe_connects 1, final count). NUL and a directory give exit 2 within ~25 ms.",
            "agent.regular_file_not_modified (section 9.6): Rust overwrites the first 5 bytes of the regular file with the request frame 00 00 00 01 0b (mtime changes) and exits 5 with AGENT_PROTOCOL_ERROR, which is also not one of the allowed refusal results. A directory and a non-existent path are refused correctly (exit 5 AGENT_UNAVAILABLE, nothing modified or created).",
            "run.batch_target.* (section 9.6): Rust passes all four; all 16 arguments reach the batch file exactly for .bat and .cmd, with and without a space in the path, and no injected command ran. The argument `a\" & break>...` decodes exactly only under the UCRT rule (Rust doubles the quote: `\"a\"\" & break>...\"`); CommandLineToArgvW splits it at the space. The harness accepts either decoding (see interpretations). Exit 0 in every case (Rust starts cmd.exe with /d, so AutoRun does not run)."]
    interp = [
        "Gating follows docs/g02/slice-contract.md section 9.6 (2026-10-06), identically for both candidates: K14 covers a named pipe and any other non-regular path as --file for profile show and tui (exit 2 within 2 s; the tui rows also require the alternate screen not to be left active, as tests/g02 tui.non_regular_file does); agent list --socket must refuse a regular file, a directory and a non-existent path without modifying anything, with exit 5 AGENT_UNAVAILABLE or exit 2 USAGE_ERROR; a .bat/.cmd target must not run any argument byte as a command, with or without a space in its path.",
        "Batch-file rows: the child is a batch file that forwards %* to argvdump.exe. 'Received exactly' means the forwarded argument decodes to the original UTF-16 code units under CommandLineToArgvW or under the UCRT (msvcrt 2008+) rules; cmd.exe has no single unescaping rule for embedded quotes, so both standard decodings are accepted. 'Refused' means exit 127, a stderr message and the child never ran. Injection is detected by files the injected `break>file` commands create. The control row run.batch_control shows the forwarding batch delivers a quoted argument and a literal %VAR% exactly, and that the detector sees an injection.",
        "tui.ctrl_c_event (CTRL_C_EVENT raised by another process) stays recorded, not gated (section 9.6 'recorded, not gated'). Resolution-order rows stay info.",
        "Review fixes applied to the script (x1-review): every parsed JSON result and every --meta-file document is validated against schemas/g02/result.schema.json; K18 value non-echo is checked for all six invalid fixtures on stdout and stderr of the --json and the plain run; pipe_connects is read after the stall-pipe helper has stopped (final count); the canary-scan criterion states exactly what is scanned (Invoke-X1 now scans every captured stream)."]
    lim = [l for l in prev['limitations'] if not l.startswith('The X1 Windows script is new') and not l.startswith('tests/native/windows/G03Common.psm1 was staged')]
    lim = [("Resolution-order rows, the lone-surrogate row and the X1 .cmd rows run.cmd_metachar_argument(_nospace_path) are recorded observations (info or non-gating), not contract verdicts; batch-file behaviour is gated by the section 9.6 rows run.batch_target.*." if l.startswith('Resolution-order, .cmd') else l) for l in lim]
    lim[0] = "One host: the owner's Windows 11 Pro 26300 x64 PC, non-elevated user. Three full runs (Windows PowerShell 5.1 twice, PowerShell 7.6.6 once) gave identical verdicts for every row; timing values differ between runs."
    lim += [
        "The section 9.6 script changes have not had an independent review. Two development runs on the host preceded the three evidence runs; they exposed two harness defects that were fixed before the evidence runs: subdirectory mtimes read through the parent's enumeration change by themselves on NTFS (now read per path against a baseline stable for 200 ms), and the batch rows required exit 0 for an exact delivery (dropped: section 9.6 does not ask for it, and cmd.exe AutoRun on this host makes it exit 1).",
        "Batch-file coverage: 16 arguments, .bat and .cmd, one path with and one without a space, under the owner's cmd.exe configuration (AutoRun configured; DelayedExpansion state not inspected; `!` arguments not tested). Arguments containing newlines, NUL, or non-ASCII were not tested as batch arguments. The batch file is resolved by full path; PATHEXT resolution of a bare name stays the info row resolution.pathext_cmd.",
        "K14 named-pipe rows use a server that accepts and never answers; a pipe server that sends a valid profile and closes was not tested.",
        "PowerShell 7 ConvertFrom-Json turns ISO-8601 strings into DateTime; the schema port treats DateTime as a string (no G02 result field holds such a string)."]
    rec = {
        'case_id': f'G02-{c}-x1-windows',
        'status': 'verified',
        'requirement_ids': prev['requirement_ids'],
        'build_commit': 'e0ead9b',
        'artifact_digest': 'sha256:' + meta[c][1],
        'environment': {
            'platform': 'windows-x64',
            'host': "owner personal PC (authorized for X1), reached over SSH into WSL2 and Windows interop; non-elevated Windows user",
            'os': envf['caption'], 'build': envf['build'], 'ubr': envf['ubr'], 'display_version': envf['display_version'], 'arch': envf['arch'],
            'powershell': ['Windows PowerShell 5.1.26100.9549 (runs s96-ps51-a, s96-ps51-b)', 'PowerShell 7.6.6 (run s96-ps7-a)'],
            'clr': envf['clr'], 'elevated': False, 'path_for_artifacts': envf['path_now'], 'path_entries_before_reduction': envf['original_path_entries'],
            'removed_env': envf['removed_env'], 'ssh_auth_sock': 'sentinel pipe name that does not exist (never unset, never the system agent pipe)',
            'cmd_autorun_configured': True,
            'console': 'pseudoconsoles (CreatePseudoConsole) or no console; no windows created',
            'candidate': c, 'candidate_commit': meta[c][0], 'artifact': f'prototypes/{c}/dist/windows-x64/heimdall-proto.exe',
            'artifact_check': 'sha256 and size equal prototypes/<c>/dist/manifest.json windows-x64 on the Mac before staging and on the host (integrity row); not rebuilt',
            'harness': {
                'path': 'tests/native/windows-g02/Invoke-G02WindowsX1.ps1', 'sha256': sha('tests/native/windows-g02/Invoke-G02WindowsX1.ps1'),
                'source_state': 'working tree on top of e0ead9b (uncommitted at run time); the staged copies equal these sha256 values (tests/evidence/artifacts/g02-r4/x1/windows-96/staged-root.sha256)',
                'supporting_sha256': supp,
                'argvdump_exe_sha256': '678efbbc7856adcd3623fac6f39fd2505d4c72ae65c4381b4e181a4a8a870f2c',
                'argvdump_build': 'rebuilt on the Mac with the recorded command (go1.27.1, GOOS=windows GOARCH=amd64 CGO_ENABLED=0 -trimpath -buildvcs=false -ldflags=-s -w); byte-identical to the X1 helper'}},
        'provider_versions': prev['provider_versions'],
        'started_at': base['rows'][0]['at'],
        'commands_or_harness': [
            'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <scratch>\\tools\\Invoke-G02WindowsX1.ps1 -Root <scratch> -OutDir <scratch>\\out\\s96-ps51-a',
            'pwsh.exe (same arguments) -OutDir <scratch>\\out\\s96-ps7-a',
            'powershell.exe (same arguments) -OutDir <scratch>\\out\\s96-ps51-b',
            'wrapper: tests/evidence/artifacts/g02-r4/x1/windows-96/winrun.sh (run inside WSL; <scratch> = %LOCALAPPDATA%\\hm-m00\\M00-T05-x1b-script)'],
        'observed_result': {
            'verdict': verdict,
            'criterion': 'every gating row of tests/native/windows-g02/Invoke-G02WindowsX1.ps1 passes for this candidate on native Windows 11 x64 under docs/g02/slice-contract.md sections 1-9.6 (section 9.6 baseline), with every harness control row passing',
            'summary': summ,
            'findings': findings,
            'harness_controls': host_rows,
            'rows': rows,
            'interpretations': interp,
            'previous_record': {
                'path': f'tests/evidence/artifacts/g02-r4/x1/prev-records/g02-{c}-x1-windows.pre-9.6.json',
                'verdict': prev['observed_result']['verdict'],
                'summary': {k: prev['observed_result']['summary'][k] for k in ('rows', 'gating', 'gating_pass', 'gating_not_pass')},
                'relation': 'same frozen artifact; the script now gates section 9.6 (8 new gating rows per candidate: run.batch_control, 4 run.batch_target.*, agent.directory_as_socket_refused, agent.nonexistent_path_as_socket_refused, tui.directory_as_file) and applies the x1-review fixes'}},
        'evidence_paths': [
            'tests/evidence/artifacts/g02-r4/x1/RESULTS.md',
            'tests/evidence/artifacts/g02-r4/x1/windows-96/s96-ps51-a',
            'tests/evidence/artifacts/g02-r4/x1/windows-96/s96-ps7-a',
            'tests/evidence/artifacts/g02-r4/x1/windows-96/s96-ps51-b',
            'tests/evidence/artifacts/g02-r4/x1/windows-96/staged-root.sha256',
            'tests/evidence/artifacts/g02-r4/x1/windows-96/winrun.sh',
            'tests/native/windows-g02',
            f'tests/evidence/artifacts/g02-r4/x1/prev-records/g02-{c}-x1-windows.pre-9.6.json'],
        'limitations': lim}
    s = json.dumps(rec, indent=1, ensure_ascii=False) + '\n'
    assert 'HEIMDALL_CANARY_' not in s.replace('[REDACTED_CANARY]', '')
    open(f'tests/evidence/g02-{c}-x1-windows.json', 'w', encoding='utf-8').write(s)
    print(c, verdict, summ['gating_pass'], '/', summ['gating'], summ['gating_not_pass'], len(rows))
