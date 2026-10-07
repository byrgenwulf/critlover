// workflow.test.mjs — unit test for the crit-hunt.js workflow's grading LOGIC.
//
// The workflow normally fans out real subagents against a target, so its control flow
// (Gate-A short-circuit, identity dedup, drop-classification, the MED floor) is otherwise
// never exercised in isolation. This harness loads the ACTUAL script body, stubs
// agent()/parallel()/pipeline()/phase()/log(), feeds synthetic findings, and asserts the
// {survivors, dropped} it produces — including that short-circuited gates never spend an
// agent call. No network, no subagents, no target. Run: `node tests/workflow.test.mjs`.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const root = process.argv[2] || path.resolve(here, '..')
const scriptPath = path.join(root, '.claude/workflows/crit-hunt.js')
const src = fs.readFileSync(scriptPath, 'utf8').replace(/^export const meta/m, 'const meta')
const AsyncFunction = (async () => {}).constructor

let fail = 0, passN = 0
const assert = (cond, msg) => { if (!cond) { console.log('FAIL: ' + msg); fail++ } else { console.log('PASS: ' + msg); passN++ } }

// Synthetic findings covering every gate outcome. f-surv2 shares f-surv's sink -> in-code dedup.
const FINDINGS = [
  { id: 'f-ref',   title: 'REFUTED bug', chain: 'src->sink', sink: 'a.py:1', reachability: 'unauth', preconditions: 'none', claimedSeverity: 'CRIT' },
  { id: 'f-dup',   title: 'DUP bug',     chain: 'src->sink', sink: 'b.py:2', reachability: 'unauth', preconditions: 'none', claimedSeverity: 'HIGH' },
  { id: 'f-low',   title: 'LOW bug',     chain: 'src->sink', sink: 'c.py:3', reachability: 'low',    preconditions: 'flag', claimedSeverity: 'CRIT' },
  { id: 'f-surv',  title: 'SURV bug',    chain: 'src->sink', sink: 'd.py:4', reachability: 'unauth', preconditions: 'none', claimedSeverity: 'CRIT' },
  { id: 'f-surv2', title: 'SURV twin',   chain: 'alt->sink', sink: 'd.py:4', reachability: 'unauth', preconditions: 'none', claimedSeverity: 'HIGH' },
]

const makeStubs = () => {
  const calls = { finder: 0, verify: 0, dup: 0, sev: 0 }
  const agent = async (prompt) => {
    if (/You are a FINDER/.test(prompt)) { calls.finder++; return { findings: FINDINGS } }
    if (/source-verifier|REFUTE/.test(prompt)) { calls.verify++; const r = /REFUTED bug/.test(prompt); return { verified: !r, brokenLink: r ? 'hop2' : undefined, notes: '' } }
    if (/DUP-CHECKER/.test(prompt)) { calls.dup++; return { dup: /DUP bug/.test(prompt), evidence: 'prior art' } }
    if (/SEVERITY RECALIBRATOR/.test(prompt)) { calls.sev++; return { severity: /LOW bug/.test(prompt) ? 'LOW' : 'HIGH', justification: '', vendorPrecedent: '' } }
    throw new Error('unexpected agent prompt: ' + prompt.slice(0, 120))
  }
  const parallel = (thunks) => Promise.all(thunks.map((t) => t()))
  const pipeline = async (items, ...stages) => Promise.all(items.map(async (it, idx) => {
    let prev
    for (const st of stages) { try { prev = await st(prev, it, idx) } catch (e) { return null } }
    return prev
  }))
  return { calls, agent, parallel, pipeline, phase: () => {}, log: () => {} }
}

const run = new AsyncFunction('args', 'agent', 'parallel', 'pipeline', 'phase', 'log', src)
const baseArgs = { repoPath: '/x', target: 't', venue: 'v', threatModelFilter: 'tmf', buckets: [{ key: 'b1', hypothesis: 'h', paths: ['p'] }] }
const idsOf = (a) => a.map((x) => x.finding.id).sort().join(',')

// --- default run (MED floor) ------------------------------------------------
{
  const s = makeStubs()
  const r = await run(baseArgs, s.agent, s.parallel, s.pipeline, s.phase, s.log)
  const reason = (id) => (r.dropped.find((d) => d.finding.id === id) || {}).dropReason || ''
  assert(r.survivors.length === 1 && r.survivors[0].finding.id === 'f-surv', 'exactly f-surv survives')
  assert(r.survivors[0].severity.severity === 'HIGH', 'survivor graded HIGH')
  assert(idsOf(r.dropped) === 'f-dup,f-low,f-ref,f-surv2', 'dropped = f-ref,f-dup,f-low,f-surv2 (got ' + idsOf(r.dropped) + ')')
  assert(/Gate A|refuted/.test(reason('f-ref')), 'f-ref dropped with a Gate-A reason')
  assert(/duplicate/.test(reason('f-dup')), 'f-dup dropped as a duplicate')
  assert(/MED/.test(reason('f-low')), 'f-low dropped below the MED floor')
  assert(/in-code dup/.test(reason('f-surv2')), 'f-surv2 logged as an in-code dedup collapse')
  assert(s.calls.verify === 4, 'source-verify ran on all 4 deduped findings (got ' + s.calls.verify + ')')
  assert(s.calls.dup === 3, 'short-circuit: dup-check ran only on the 3 verified, not the refuted one (got ' + s.calls.dup + ')')
  assert(s.calls.sev === 2, 'short-circuit: severity ran only on the 2 verified+non-dup (got ' + s.calls.sev + ')')
}

// --- rubricRewardsLowInfo opt-in keeps a sub-MED survivor -------------------
{
  const s = makeStubs()
  const r = await run({ ...baseArgs, rubricRewardsLowInfo: true }, s.agent, s.parallel, s.pipeline, s.phase, s.log)
  assert(r.survivors.some((x) => x.finding.id === 'f-low'), 'rubricRewardsLowInfo=true keeps the LOW survivor')
}

console.log(`\n== workflow logic: ${passN} passed, ${fail} failed ==`)
process.exit(fail === 0 ? 0 : 1)
