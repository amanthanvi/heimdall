export const meta = {
  name: 'heimdall-m00-g02-round4-x2d',
  description: 'Heimdall G02 round 4 X2 rerun: the two T1 opus1 cells in fresh workspaces (the earlier ones continued an interrupted attempt), same prompts as x2c, one chain',
  phases: [
    { title: 'Implement', detail: 'T1-go-opus1 and T1-rust-opus1 in fresh workspaces, one at a time' },
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

const RUNS = [{ r: 'opus1', model: 'opus' }, { r: 'opus2', model: 'opus' }, { r: 'sonnet1', model: SONNET }]
const cells = []
for (const run of RUNS) for (const t of ['T1', 'T2', 'T3', 'T4']) for (const lang of ['go', 'rust']) cells.push({ t, lang, run, id: `${t}-${lang}-${run.r}` })
const wsMap = {}; for (const [k, v] of Object.entries(args.ws)) wsMap[k] = { ...v, manifest: v.manifest.replace("HIDDEN/", HIDDEN + "/") }
const done = args.done || {}
const implPrompt = (c, w) => `You are a careful maintainer of an open-source security tool: a small prototype CLI/TUI written in ${c.lang === 'go' ? 'Go (Bubble Tea)' : 'Rust (Ratatui)'}.
WORKSPACE: ${w.workspace} — cd there first. Work ONLY inside it, plus a scratch directory ${w.workspace}/../scratch/ that you create. Do not read any other directory on this machine besides system tools and toolchains (no other checkouts, no other workspaces, nothing under your home directory except toolchain caches). The task is in TASK.md; the binding contract is docs/g02/slice-contract.md; the prototype is in prototypes/${c.lang}/ (its REPORT.md describes its design).
FIRST: git init the workspace and commit everything as the starting point (so your diff is measurable).
DO: implement TASK.md with production-quality code and tests in the prototype's own test framework. Build the darwin-arm64 and linux-arm64 artifacts with prototypes/${c.lang}/build.sh (all targets must still compile). Run the unit tests. Run the shared harness read-only from the workspace: tests/g02/.venv/bin/python tests/g02/conformance.py --bin <darwin artifact> --candidate ${c.lang} --out <scratch>/harness-darwin.json --artifacts-dir <scratch>/harness-darwin, and on Linux: sh tests/g02/linux/run.sh --artifact-dir <linux-arm64 artifact dir> --candidate ${c.lang} --out <scratch>/harness-linux.json (see tests/g02/README.md); TASK.md says which harness results are expected.
RULES: never print or write secrets; no network listeners except loopback/Unix sockets; stop only processes you started, by exact PID; unset SSH_AUTH_SOCK; do not touch ~/.ssh or any real SSH agent or keychain.
OUTPUT (write these files with the shell, e.g. cat > file <<'EOF', because the file-writing tool may refuse report files): write ${w.workspace}/../out/: diff.patch (git diff from your starting commit, excluding build outputs), REPORT.md (what you changed and why, test and harness results with real exit codes, known gaps), artifacts.json (paths and sha256 of the darwin-arm64 and linux-arm64 artifacts).
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

let t4lock = Promise.resolve()
async function chain(c) {
  const w = wsMap[c.id]
  if (!w) return { cell: c.id, error: 'no workspace' }
  const prev = done[c.id] || {}
  let impl = prev.impl
  if (!impl) {
    if (c.t === 'T4') {
      let release; const mine = new Promise(r => { release = r }); const before = t4lock; t4lock = before.then(() => mine)
      await before
      try { impl = await A(implPrompt(c, w), { label: `impl-${c.id}`, phase: 'Implement', schema: REPORT, model: c.run.model, effort: 'high' }) } finally { release() }
    } else impl = await A(implPrompt(c, w), { label: `impl-${c.id}`, phase: 'Implement', schema: REPORT, model: c.run.model, effort: 'high' })
  }
  if (!impl) return { cell: c.id, error: 'impl failed' }
  const ev = prev.ev || await A(evalPrompt(c, w, impl), { label: `eval-${c.id}`, phase: 'Evaluate', schema: EVAL, model: SONNET, effort: 'high' })
  if (!ev) return { cell: c.id, impl, error: 'eval failed' }
  const review = prev.review || await A(reviewPrompt(c, w, ev), { label: `review-${c.id}`, phase: 'Evaluate', schema: CODEREV, model: 'opus', effort: 'high' })
  return { cell: c.id, task: c.t, lang: c.lang, run: c.run.r, workspace: w.workspace, impl, ev, review, error: review ? null : 'review failed' }
}
const queue = cells.filter(c => wsMap[c.id])
const x2 = []
async function worker() { while (queue.length) { const c = queue.shift(); const r = await chain(c); x2.push(r); log(`${c.id}: ${r.error || 'done'}`) } }
await Promise.all([worker()])
return { x2 }
