export const meta = {
  name: 'heimdall-m00-g02-round4-x2b',
  description: 'Heimdall G02 round 4 X2 (second attempt): close the transcript-audit gap and minor pack issues, independent recheck, build isolated workspaces, then 24 implementation cells in 3 batches with hidden-test evaluation and code review',
  phases: [
    { title: 'TaskPack', detail: 'finish interrupted pack fix; independent recheck' },
    { title: 'Setup', detail: 'build 24 isolated implementer workspaces' },
    { title: 'Implement', detail: '3 batches (opus1, opus2, sonnet1) x 4 tasks x 2 languages' },
    { title: 'Evaluate', detail: 'hidden tests, harness regression, unit tests, independent code review' },
  ],
}
const REPO = '<home>/GitRepos/heimdall'
const SONNET = 'claude/claude-sonnet-5-5'
const HIDDEN = '<home>/.local/share/heimdall-m00/r4-hidden'
const EV = 'tests/evidence/artifacts/g02-r4'
const CMD = { type: 'array', items: { type: 'object', required: ['command', 'exit_code', 'observed'], properties: { command: { type: 'string' }, exit_code: { type: ['integer', 'null'] }, observed: { type: 'string' } } } }
const REPORT = { type: 'object', required: ['task_id', 'status', 'files_changed', 'commands_run', 'escalations', 'limitations', 'summary'], properties: {
  task_id: { type: 'string' }, status: { enum: ['not_started', 'in_progress', 'blocked', 'implemented_unverified', 'verified', 'deferred_with_decision'] },
  files_changed: { type: 'array', items: { type: 'string' } }, commands_run: CMD, escalations: { type: 'array', items: { type: 'string' } }, limitations: { type: 'array', items: { type: 'string' } }, summary: { type: 'string' } } }
const FAIR = { type: 'object', required: ['fair', 'issues', 'summary'], properties: {
  fair: { type: 'boolean' }, issues: { type: 'array', items: { type: 'object', required: ['severity', 'task', 'description'], properties: { severity: { enum: ['blocker', 'major', 'minor'] }, task: { type: 'string' }, description: { type: 'string' } } } }, summary: { type: 'string' } } }
const WS = { type: 'object', required: ['workspaces', 'summary'], properties: {
  workspaces: { type: 'array', items: { type: 'object', required: ['cell', 'workspace', 'manifest', 'ok'], properties: { cell: { type: 'string' }, workspace: { type: 'string' }, manifest: { type: 'string' }, ok: { type: 'boolean' } } } }, summary: { type: 'string' } } }
const EVAL = { type: 'object', required: ['cell', 'built', 'hidden', 'harness', 'unit_tests', 'summary', 'commands_run'], properties: {
  cell: { type: 'string' }, built: { type: 'boolean' },
  hidden: { type: 'object', required: ['darwin', 'linux'], properties: {
    darwin: { type: 'object', properties: { passed: { type: 'integer' }, total: { type: 'integer' }, failed_ids: { type: 'array', items: { type: 'string' } } } },
    linux: { type: 'object', properties: { passed: { type: 'integer' }, total: { type: 'integer' }, failed_ids: { type: 'array', items: { type: 'string' } } } },
    t1_fixed_regressed: { type: 'object', description: 'T1 only: per platform, baseline-failing checks fixed and baseline-passing checks regressed (score.py)' } } },
  harness: { type: 'object', required: ['darwin', 'linux'], properties: { darwin: { type: 'object', properties: { passed: { type: 'integer' }, total: { type: 'integer' }, failed_ids: { type: 'array', items: { type: 'string' } } } }, linux: { type: 'object', properties: { passed: { type: 'integer' }, total: { type: 'integer' }, failed_ids: { type: 'array', items: { type: 'string' } } } } } },
  unit_tests: { type: 'object', properties: { exit_code: { type: ['integer', 'null'] }, summary: { type: 'string' } } },
  all_targets_build: { type: 'boolean' },
  diff_stats: { type: 'object', properties: { files: { type: 'integer' }, insertions: { type: 'integer' }, deletions: { type: 'integer' } } },
  commands_run: CMD, summary: { type: 'string' } } }
const CODEREV = { type: 'object', required: ['cell', 'defects', 'spec_conformance', 'test_quality', 'clarity', 'summary'], properties: {
  cell: { type: 'string' },
  defects: { type: 'array', items: { type: 'object', required: ['severity', 'description', 'location'], properties: { severity: { enum: ['blocker', 'major', 'minor'] }, description: { type: 'string' }, location: { type: 'string' } } } },
  spec_conformance: { type: 'integer', minimum: 1, maximum: 5 }, test_quality: { type: 'integer', minimum: 1, maximum: 5 }, clarity: { type: 'integer', minimum: 1, maximum: 5 },
  summary: { type: 'string' } } }
const ORCH = `
You are a subagent on Heimdall milestone M00, G02 round 4 X2 (orchestration side; you may know about the hidden pack). Repository: ${REPO}; cd there first. Read docs/g02/round4-plan.md. CLAUDE.md rules apply. Never describe expected output as observed; report real exit codes. Do not git commit/push. Write only inside your WRITE OWNERSHIP. Never touch the owner's ~/.ssh, real agent (unset SSH_AUTH_SOCK), login keychain or live hosts; no public listeners; no sudo or system installs; stop only exact PIDs you started; no raw process command lines or env dumps; no absolute home paths or full HEIMDALL_CANARY_ values in anything written to the repository. Do not touch Docker resources labeled heimdall.fixture.`
async function A(prompt, opts) {
  let r = await agent(prompt, opts)
  if (!r) { log(`retrying ${opts.label}`); r = await agent(prompt, { ...opts, label: `${opts.label}-retry` }) }
  return r
}

phase('TaskPack')
const fix = await A(`${ORCH}
TASK ID: M00-T05-r4-taskpack-fix2
OBJECTIVE: Close the issues an independent recheck found in the X2 task pack at ${HIDDEN} (recheck result: ${REPO}/tests/evidence/artifacts/m00-wf7/../g02-r4/x2/taskpack-recheck/ if present, and summarized here). Previous fix report and recheck are in the workflow journal; key points:
- MAJOR: audit-transcript.py misses access through relative paths, cd, and globs. It reported CLEAN for (1) 'cd /tmp && diff -r hm-r4/seeded/go x2ws-a1b2/heimdall/prototypes/go', (2) 'ls ../.. ; diff -r ../../hm-r4/seeded/go prototypes/go', (3) 'diff -r /tmp/hm*/M00*/base/prototypes/go prototypes/go', (4) 'cat ../../x2ws-zz99/...'. Also: implementer agents START with their cwd at the repository root (${REPO}), which holds the unseeded base prototypes (base = HEAD prototypes), so any command run before cd into the workspace, or any relative path from the repo root, must be flagged. Make the audit conservative: for every tool call, resolve the effective cwd (transcript cwd field, plus any cd in the command), and flag any path argument, relative or absolute, glob, ~ or $VAR form, that resolves or could expand outside the cell's workspace and its own scratch, except an allowlist of toolchain/system locations (go/cargo/rustup/zig caches and installs, /usr, /bin, /opt/homebrew, /Library/Developer, /System, /dev, /private/var/folders tmp for compilers, docker CLI). Flag Read/Glob/Grep tool calls on paths outside the workspace too. Output per-cell verdict CLEAN or SUSPECT with the offending call indices (no transcript text). Test it on the four crafted cases above, a cwd-at-repo case, and on a clean crafted transcript; all must classify correctly.
- The unseeded copies in /tmp/hm-r4 were deleted by the orchestrator (disk was full). The seeded trees now live at ${HIDDEN}/seeded-trees/{go,rust} (digests unchanged, BASE.json updated). Update make-workspace.sh and any script that used /tmp/hm-r4/seeded. Use scratch under ${HIDDEN}/../r4-scratch/ (not /tmp/hm-r4) from now on.
- minor: score.py must require --expect-sha256 and check the language (record it in run.py output and verify it in score.py).
- minor: run every pack Python with -B / PYTHONDONTWRITEBYTECODE=1 so no __pycache__ (home paths) is recreated.
- minor: make-workspace.sh must check the resolved destination before any mkdir.
- ORCHESTRATOR DECISION (record it in README): T2.ascii_fold_only counts toward all_pass for both languages; the spec states the ASCII-only rule explicitly.
- Add to the evaluator protocol: after evaluation, delete heavy build intermediates in the cell workspace (Rust target/ except the built artifacts copied to the cell's out/, Go build cache dirs inside the workspace) because the host disk is nearly full; keep the artifacts the reviewer needs in out/.
Re-run verify-matrix.sh once on darwin and Linux with the pinned base (expected: baselines red on T1-T3, seeded red / base green on T4, positive controls green). Disk is tight (about 30 GB free): remove your own build intermediates when done.
WRITE OWNERSHIP: ${HIDDEN}/** ; ${HIDDEN}/../r4-scratch/** ; ${EV}/x2/specs/** .
Return the structured report.`, { label: 'taskpack-fix2', phase: 'TaskPack', schema: REPORT, model: 'opus', effort: 'high' })
const recheck = await A(`${ORCH}
TASK ID: M00-T05-r4-taskpack-recheck2
ROLE: Independent recheck (you did not write the fixes). Earlier rechecks found: baseline drift, implementer isolation, T1 scoring (resolved), then a major gap: the transcript audit missed relative/cd/glob access and access from the repository root (implementer agents start with cwd = ${REPO}, which holds the unseeded base prototypes). Fix report: ${JSON.stringify(fix).slice(0, 4000)}
CHECK concretely in ${HIDDEN}: craft at least 8 adversarial transcripts (relative escapes, cd chains, globs, $HOME/~ forms, Read/Grep tool calls outside, commands run before cd from the repo root, symlink tricks, a clean one) and confirm audit-transcript.py classifies them; build one workspace with make-workspace.sh and confirm its contents; confirm score.py requires --expect-sha256 and checks the language; confirm no __pycache__ appears after a run; run verify-matrix.sh for one task on darwin. Blocker/major only if an implementer could gain an undetected advantage or tests mis-score.
WRITE OWNERSHIP: ${EV}/x2/taskpack-recheck2/** ; ${HIDDEN}/../r4-scratch/recheck2/** .
Return the structured verdict.`, { label: 'taskpack-recheck2', phase: 'TaskPack', schema: FAIR, model: 'opus', effort: 'high' })
if (!recheck || !recheck.fair || recheck.issues.some(i => i.severity !== 'minor')) {
  log('task pack recheck not clean: stopping before implementation')
  return { fix, recheck, stopped: true }
}

phase('Setup')
const RUNS = [{ r: 'opus1', model: 'opus' }, { r: 'opus2', model: 'opus' }, { r: 'sonnet1', model: SONNET }]
const cells = []
for (const run of RUNS) for (const t of ['T1', 'T2', 'T3', 'T4']) for (const lang of ['go', 'rust']) cells.push({ t, lang, run, id: `${t}-${lang}-${run.r}` })
const ws = await A(`${ORCH}
TASK ID: M00-T05-r4-x2-workspaces
OBJECTIVE: Build one isolated implementer workspace per X2 cell with ${HIDDEN}/make-workspace.sh (HM_REPO=${REPO}). Cells: ${JSON.stringify(cells.map(c => ({ cell: c.id, task: c.t, lang: c.lang })))}.
For each cell use --dest /tmp/x2ws-<8 random hex>/heimdall (a fresh neutral directory per cell; the name must not contain the task, language or run) and --manifest ${HIDDEN}/workspaces/<cell>.json. Verify each build exit 0 and that the workspace has no .git, no hidden material, no other language. Return the mapping.
WRITE OWNERSHIP: /tmp/x2ws-*/** ; ${HIDDEN}/workspaces/** .
Return the structured mapping.`, { label: 'x2-workspaces', phase: 'Setup', schema: WS, model: SONNET, effort: 'medium' })
const wsMap = {}
for (const w of (ws ? ws.workspaces : [])) if (w.ok) wsMap[w.cell] = w

const implPrompt = (c, w) => `You are a careful maintainer of an open-source security tool: a small prototype CLI/TUI written in ${c.lang === 'go' ? 'Go (Bubble Tea)' : 'Rust (Ratatui)'}.
WORKSPACE: ${w.workspace} — cd there first. Work ONLY inside it, plus a scratch directory ${w.workspace}/../scratch/ that you create. Do not read any other directory on this machine besides system tools and toolchains (no other checkouts, no other workspaces, nothing under your home directory except toolchain caches). The task is in TASK.md; the binding contract is docs/g02/slice-contract.md; the prototype is in prototypes/${c.lang}/ (its REPORT.md describes its design).
FIRST: git init the workspace and commit everything as the starting point (so your diff is measurable).
DO: implement TASK.md with production-quality code and tests in the prototype's own test framework. Build the darwin-arm64 and linux-arm64 artifacts with prototypes/${c.lang}/build.sh (all targets must still compile). Run the unit tests. Run the shared harness read-only from the workspace: tests/g02/.venv/bin/python tests/g02/conformance.py --bin <darwin artifact> --candidate ${c.lang} --out <scratch>/harness-darwin.json --artifacts-dir <scratch>/harness-darwin, and on Linux: sh tests/g02/linux/run.sh --artifact-dir <linux-arm64 artifact dir> --candidate ${c.lang} --out <scratch>/harness-linux.json (see tests/g02/README.md); TASK.md says which harness results are expected.
RULES: never print or write secrets; no network listeners except loopback/Unix sockets; stop only processes you started, by exact PID; unset SSH_AUTH_SOCK; do not touch ~/.ssh or any real SSH agent or keychain.
OUTPUT: write ${w.workspace}/../out/: diff.patch (git diff from your starting commit, excluding build outputs), REPORT.md (what you changed and why, test and harness results with real exit codes, known gaps), artifacts.json (paths and sha256 of the darwin-arm64 and linux-arm64 artifacts).
Return a structured report (task_id ${c.id}).`
const evalPrompt = (c, w, impl) => `${ORCH}
TASK ID: M00-T05-r4-x2-eval-${c.id}
ROLE: Evaluator of one X2 result. You fix nothing. Cell ${c.id} (task ${c.t}, ${c.lang}, run ${c.run.r}). Workspace ${w.workspace}; outputs ${w.workspace}/../out/; cell manifest ${w.manifest}. Implementer report: ${JSON.stringify(impl).slice(0, 2000)}
Follow the evaluator protocol in ${HIDDEN}/README.md exactly (digest checks, hidden tests on darwin and Linux with per-platform binaries, score.py for T1 fixed/regressed, full 2.4.2 harness both platforms with the task's expected result, unit tests, all-target build). Rebuild from the workspace if artifacts are missing or digests differ; if it does not build, built=false. Rerun failing hidden checks up to 2 more times and report flakiness. Copy the implementer's out/ files and your results (scrubbed: no absolute home paths, no hidden-dir paths, no canary values) to ${REPO}/${EV}/x2/runs/${c.id}/.
WRITE OWNERSHIP: ${REPO}/${EV}/x2/runs/${c.id}/** ; ${w.workspace}/../eval/** ; and, after your evaluation, deletion of build intermediates inside ${w.workspace} as the evaluator protocol says (keep out/ and the artifacts the reviewer needs).
Return the structured evaluation.`
const reviewPrompt = (c, w, ev) => `${ORCH}
TASK ID: M00-T05-r4-x2-review-${c.id}
ROLE: Independent code reviewer of one X2 change (you did not write it). Review ${w.workspace}/../out/diff.patch against the spec ${w.workspace}/TASK.md and the surrounding code in ${w.workspace}/prototypes/${c.lang}/. Use the same rubric for any language: correctness and edge cases (signals/process/terminal/parsing), security (input handling, value non-echo, resource bounds), spec conformance, test quality, clarity and maintainability for future agents. For T2 check ASCII-only case folding by reading the code (the tests do not). Evaluation (do not redo it): ${JSON.stringify(ev).slice(0, 2000)}. You may run read-only probes against the built artifacts.
WRITE OWNERSHIP: ${REPO}/${EV}/x2/runs/${c.id}/review/** ; deletion of the cell directory below.
FINALLY (isolation and disk): verify that ${REPO}/${EV}/x2/runs/${c.id}/ holds diff.patch, REPORT.md, artifacts.json and the evaluator's results, then delete the whole cell directory $(dirname ${w.workspace}) so later cells cannot read this solution. Report whether you deleted it.
Return the structured review (scores 1-5).`

const x2 = []
for (const run of RUNS) {
  phase('Implement')
  const batch = cells.filter(c => c.run.r === run.r && wsMap[c.id])
  log(`batch ${run.r}: ${batch.length} cells`)
  const res = await pipeline(batch,
    c => A(implPrompt(c, wsMap[c.id]), { label: `impl-${c.id}`, phase: 'Implement', schema: REPORT, model: c.run.model, effort: 'high' }),
    (impl, c) => A(evalPrompt(c, wsMap[c.id], impl), { label: `eval-${c.id}`, phase: 'Evaluate', schema: EVAL, model: SONNET, effort: 'high' }).then(ev => ({ impl, ev })),
    (r, c) => A(reviewPrompt(c, wsMap[c.id], r.ev), { label: `review-${c.id}`, phase: 'Evaluate', schema: CODEREV, model: 'opus', effort: 'high' }).then(rv => ({ cell: c.id, task: c.t, lang: c.lang, run: c.run.r, workspace: wsMap[c.id].workspace, ...r, review: rv })))
  x2.push(...res)
}
return { fix, recheck, ws, x2 }
