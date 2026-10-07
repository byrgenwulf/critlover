/*
 * crit-hunt.js — critlover finder fan-out + honest grading (pipeline stages 3-4)
 * ===========================================================================
 *
 * AUTHORIZED research + RESPONSIBLE DISCLOSURE only. Run this ONLY against an
 * in-scope, authorized target (a public bug-bounty program, or the hunter's own
 * systems). Honor the vendor's published threat model and trust-boundary
 * carve-outs — attack AROUND the carve-outs, never report into them.
 *
 * WHAT IT DOES
 *   Phase 'Find'   — one finder agent per attack-surface bucket, in parallel.
 *                    Each finder carries the vendor threat-model filter, its own
 *                    crit hypothesis, and the reachability bar; it reports CHAINS,
 *                    not exploits. Findings are then de-duplicated in plain code.
 *   Phase 'Verify' — each finding is pipelined through three graders:
 *                      (a) source-verify  — REFUTE and trace every link in repoPath
 *                      (b) dup-check       — vs advisories + open PRs/issues
 *                      (c) severity-recalibrate — vs the vendor's OWN precedent
 *                    Only findings that are verified AND non-dup AND still
 *                    CRIT/HIGH/MED survive. The gap between claimed and survived
 *                    severity is the "overclaim tax" — logged, because that gap is
 *                    the whole point of the harness.
 *   Returns        — { survivors, dropped }, each annotated with its grading record
 *                    (and, for drops, the reason). Feed survivors into templates/
 *                    SUBMISSION.md and the whole tally into templates/PROGRESS.md.
 *
 * NOT ITS LANE (the human's lane): actually FILING through the official program,
 * writing/running any exploit, and LAB VALIDATION of a chain. This harness only
 * prepares a write-up for a human to review and file. It never auto-submits and
 * never weaponizes.
 *
 * USAGE
 *   Invoke the Workflow runner with this script and an `args` object:
 *     {
 *       repoPath:          "/abs/path/to/local/checkout",   // source-review target
 *       target:            "owner/repo @ <sha>",            // human label
 *       venue:             "huntr | ZDI | Google OSS VRP | vendor GHSA",
 *       threatModelFilter: "<in-scope / carve-outs / severity rubric, as text>",
 *       buckets: [ { key, hypothesis, paths:[...] }, ... ],  // from stage 2 (bucket design)
 *       knownAdvisories:   "<optional: CVE/GHSA/PR/issue prior art, as text>",
 *       rubricRewardsLowInfo: false,  // optional — true also keeps LOW/INFO survivors
 *       keepSeverities:    ["CRIT","HIGH","MED"]  // optional — override the filing floor outright
 *     }
 * STAGE SCOPE: this is stages 3-4 (fan-out + the three grading gates). Stage 5 (the
 * SUBMISSION / PROGRESS write-up) has no filesystem here and is the human's / skill's step;
 * the returned {survivors, dropped} are its inputs.
 *   Scale the bucket list to the surface map; empty buckets => nothing to do.
 *   Resume with { scriptPath, resumeFromRunId } after an edit or pause.
 */

export const meta = {
  name: 'crit-hunt',
  description: 'Fan out one finder per attack-surface bucket, then honestly grade every claim (source-verify -> dup-check -> severity-recalibrate) and keep only survivors. Authorized research + responsible disclosure only; a human files and does lab validation.',
  whenToUse: 'Pipeline stages 3-4 of the critlover harness (fan-out + the three grading gates; stage 5 write-up is the human\'s step): honest grading of an in-scope, AUTHORIZED open-source target. Expects args {repoPath, target, venue, threatModelFilter, buckets:[{key,hypothesis,paths}], knownAdvisories?, rubricRewardsLowInfo?, keepSeverities?}.',
  phases: [
    { title: 'Find', detail: 'One finder agent per bucket (parallel barrier), each carrying the threat-model filter, its crit hypothesis, and the reachability bar; report the chain not an exploit. Dedup by title+sink in plain code.' },
    { title: 'Verify', detail: 'Pipeline each finding (no barrier): source-verify to REFUTE every link in repoPath -> dup-check vs advisories/PRs/issues -> severity-recalibrate vs vendor precedent. Keep only verified, non-dup, CRIT/HIGH/MED survivors.' },
  ],
}

// ---------------------------------------------------------------------------
// Inputs (from the global `args`) — defensive defaults so a run is self-describing.
// ---------------------------------------------------------------------------
const A = args || {}
const repoPath = A.repoPath || '(repoPath not supplied)'
const target = A.target || '(target not supplied)'
const venue = A.venue || '(venue not supplied)'
const threatModelFilter = A.threatModelFilter || '(no threat-model filter supplied — treat EVERYTHING as potentially carved out and confirm scope before trusting any finding)'
const buckets = Array.isArray(A.buckets) ? A.buckets : []
const knownAdvisories = A.knownAdvisories || '(none supplied — search advisories / PRs / issues from scratch)'

// MED is the DEFAULT filing floor (CLAUDE.md canon). A venue whose rubric explicitly
// rewards Low/Info can opt in with args.rubricRewardsLowInfo=true, or override the set
// outright with args.keepSeverities — so the workflow never silently buries a
// rubric-supported sub-MED finding.
const KEEP_SEVERITIES = (Array.isArray(A.keepSeverities) && A.keepSeverities.length)
  ? A.keepSeverities
  : (A.rubricRewardsLowInfo ? ['CRIT', 'HIGH', 'MED', 'LOW', 'INFO'] : ['CRIT', 'HIGH', 'MED'])

// Shared reachability bar — who can trigger it; network / guest-unprivileged?
const REACHABILITY_BAR = [
  'REACHABILITY BAR — a candidate only counts if you can name ALL of:',
  '  - Trigger actor: unauth network client | authenticated low-priv user | guest-unprivileged |',
  '    guest-root | local user. Network-reachable or guest-unprivileged is the high-value tier;',
  '    privileged / local-only is a downgrade.',
  '  - Entry channel: network endpoint | IPC | parsed file on open | queue message | guest->host.',
  '  - Precondition budget: default config, or a non-default flag / feature gate? Each extra',
  '    precondition is a downgrade.',
  '  A sink behind an auth gate, or inside a venue carve-out, does NOT clear the bar — drop it.',
].join('\n')

// ---------------------------------------------------------------------------
// Schemas — one per agent call. Each is {type:'object', properties, required⊆properties}.
// ---------------------------------------------------------------------------
const FINDER_SCHEMA = {
  type: 'object',
  properties: {
    findings: {
      type: 'array',
      description: 'Reachable bug-chain candidates for this bucket. Empty is a valid, valuable answer.',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string', description: 'stable id, e.g. "<bucketKey>-1"' },
          title: { type: 'string', description: 'short, specific' },
          chain: { type: 'string', description: 'source -> transform(s) -> sink as file:line hops (no exploit payload)' },
          sink: { type: 'string', description: 'the dangerous sink (symbol + file:line)' },
          reachability: { type: 'string', description: 'trigger actor + entry channel' },
          preconditions: { type: 'string', description: 'config / flags / feature gates required' },
          claimedSeverity: { type: 'string', enum: ['CRIT', 'HIGH', 'MED', 'LOW', 'INFO'] },
        },
        required: ['id', 'title', 'chain', 'sink', 'reachability', 'preconditions', 'claimedSeverity'],
      },
    },
  },
  required: ['findings'],
}

const VERIFY_SCHEMA = {
  type: 'object',
  properties: {
    verified: { type: 'boolean', description: 'true ONLY if every link holds in source AND untrusted input genuinely reaches the sink' },
    brokenLink: { type: 'string', description: 'optional — the first hop that does not hold; omit if verified' },
    notes: { type: 'string', description: 'what you opened and what you concluded' },
  },
  required: ['verified', 'notes'],
}

const DUP_SCHEMA = {
  type: 'object',
  properties: {
    dup: { type: 'boolean', description: 'true if any advisory / PR / issue already covers this path' },
    evidence: { type: 'string', description: 'what you searched and what you found (or did not find)' },
  },
  required: ['dup', 'evidence'],
}

const SEVERITY_SCHEMA = {
  type: 'object',
  properties: {
    severity: { type: 'string', enum: ['CRIT', 'HIGH', 'MED', 'LOW', 'INFO'] },
    justification: { type: 'string', description: 'reasoning tied to the reachability tax and impact' },
    vendorPrecedent: { type: 'string', description: 'the vendor ratings for similar bugs you scored against' },
  },
  required: ['severity', 'justification', 'vendorPrecedent'],
}

// ---------------------------------------------------------------------------
// Prompt builders.
// ---------------------------------------------------------------------------
const finderId = (f, idx) => (f && f.id) ? f.id : ('#' + idx)

const finderPrompt = (bucket) => {
  const bucketKey = bucket.key || 'unnamed-bucket'
  const bucketHypothesis = bucket.hypothesis || '(no hypothesis seeded — scan this bucket for reachable crit chains; stay default-skeptical)'
  const bucketPaths = Array.isArray(bucket.paths)
    ? bucket.paths.join(', ')
    : (bucket.paths ? String(bucket.paths) : '(whole repo)')
  return [
    'ROLE: You are a FINDER for the "' + bucketKey + '" bucket. Source-review ONLY of the local checkout at ' + repoPath + '.',
    'You find and PROVE reachable bug chains in ' + target + '. You do NOT write or run exploits.',
    '',
    'TARGET: ' + target + '    VENUE: ' + venue,
    'BUCKET PATHS (start here, then follow the data flow wherever it goes): ' + bucketPaths,
    '',
    'THREAT-MODEL FILTER (honor every carve-out — a chain that lands inside a carve-out is dead on arrival):',
    threatModelFilter,
    '',
    'HYPOTHESIS (one specific crit for this bucket — not "look for bugs"):',
    bucketHypothesis,
    '',
    REACHABILITY_BAR,
    '',
    'DUP-CHECK DUTY: note whether the path looks already-known (advisory / PR / issue). The grading pass confirms it; do not file blind.',
    '',
    'REPORT THE CHAIN, NOT AN EXPLOIT. No weaponized payloads, no PoC, no exploit code. Cite real file:line hops',
    '(source -> transform(s) -> sink), the untrusted input, and the guard(s) that fail to stop it. If you cannot',
    'source-verify a hop, say so and treat it as a lead, not a chain. Default-skeptical: when torn between two',
    'severities, pick the LOWER.',
    '',
    'Return findings per the schema. Give each a stable id (e.g. "' + bucketKey + '-1"). Return an EMPTY findings',
    'array if nothing clears the reachability bar — that is a valid and valuable answer.',
  ].join('\n')
}

const sourceVerifyPrompt = (finding) => [
  'ROLE: You are a SKEPTICAL source-verifier. Your job is to REFUTE this finding, not to confirm it.',
  'Work ONLY from the local source at ' + repoPath + '. Open every hop yourself; trust NONE of the finder prose.',
  '',
  'TARGET: ' + target,
  'FINDING ' + finding.id + ': ' + finding.title,
  'CLAIMED CHAIN: ' + finding.chain,
  'CLAIMED SINK: ' + finding.sink,
  'CLAIMED REACHABILITY: ' + finding.reachability,
  'CLAIMED PRECONDITIONS: ' + finding.preconditions,
  '',
  'Trace each link source -> transform(s) -> sink in the ACTUAL source. For EACH hop ask: does the line exist and',
  'say what is claimed? Does untrusted input really reach the sink with no validation / escaping / type check in',
  'between? Is the "missing" guard truly absent — not present on a parent, caller, decorator, middleware, or',
  'config default?',
  '',
  'Set verified=true ONLY if every link holds and untrusted input genuinely reaches the sink. If ANY hop fails,',
  'set verified=false and name the first broken hop in brokenLink. When uncertain, default to verified=false.',
  'Report only — do not write or run any exploit.',
].join('\n')

const dupCheckPrompt = (finding) => [
  'ROLE: You are a DUP-CHECKER. Decide whether this finding is already known. When in doubt, lean dup=true —',
  'filing a duplicate wastes the venue\'s and the maintainers\' time.',
  '',
  'TARGET: ' + target + '    VENUE: ' + venue,
  'FINDING ' + finding.id + ': ' + finding.title,
  'SINK: ' + finding.sink,
  'CHAIN: ' + finding.chain,
  '',
  'KNOWN ADVISORIES / PRIOR ART supplied by the operator:',
  knownAdvisories,
  '',
  'Check, by the sink symbol and the file path: (1) published advisories — CVE / GHSA / NVD and the vendor\'s own',
  'advisories; (2) in-flight work — merged PRs, OPEN PRs, OPEN issues; (3) incomplete-fix siblings — if a sibling',
  'path was just patched, is THIS the unpatched remainder (novel: dup=false) or the same path (dup=true)? Use the',
  'supplied prior art first; reach for repository / web search tools (via ToolSearch) if they are available.',
  'Set dup=true if any hit covers this path. Put what you searched and what you found in evidence.',
].join('\n')

const severityPrompt = (acc) => {
  const f = acc.finding
  const verifyLine = acc.verify
    ? ('verified=' + acc.verify.verified + (acc.verify.brokenLink ? (', brokenLink=' + acc.verify.brokenLink) : ''))
    : '(source-verify result unavailable)'
  return [
    'ROLE: You are a SEVERITY RECALIBRATOR. Re-score this finding against THE VENDOR\'S OWN precedent — not',
    'CVSS-on-autopilot, not the finder\'s claim. The finder\'s claimedSeverity is probably inflated; the overclaim',
    'tax is real (in the research this harness was built from, ~4/4 and 5/6 CRIT claims were overclaimed).',
    '',
    'TARGET: ' + target + '    VENUE: ' + venue,
    'FINDING ' + f.id + ': ' + f.title,
    'CHAIN: ' + f.chain,
    'SINK: ' + f.sink,
    'REACHABILITY: ' + f.reachability,
    'PRECONDITIONS: ' + f.preconditions,
    'FINDER CLAIMED: ' + f.claimedSeverity,
    'SOURCE-VERIFY RESULT: ' + verifyLine,
    '',
    'THREAT-MODEL FILTER (if the vendor already excludes this actor / channel, it is NOT a vuln here — score it LOW/INFO):',
    threatModelFilter,
    '',
    'Pull the venue rubric and 3-5 of the vendor\'s OWN past ratings for similar bugs, and score against THAT.',
    'Apply the reachability tax: downgrade for every precondition (auth, non-default flag, local-only, needs-root,',
    'needs-a-second-bug). CRIT requires ALL of: unauth-or-low-priv trigger + network-or-equivalent reach + serious',
    'impact (RCE / auth-bypass / memory corruption) + default config. A tie between two ratings resolves to the',
    'LOWER. Put the vendor ratings you compared against in vendorPrecedent and your reasoning in justification.',
  ].join('\n')
}

// ---------------------------------------------------------------------------
// Phase 'Find' — fan out one finder per bucket (barrier), then dedup in plain code.
// A barrier is correct here: dedup needs the full result set before verification.
// ---------------------------------------------------------------------------
phase('Find')

if (buckets.length === 0) {
  log('crit-hunt: args.buckets is empty — nothing to fan out. Design buckets (stage 2) first.')
  return { survivors: [], dropped: [] }
}

log('Find: fanning out ' + buckets.length + ' finder(s) over ' + target + ' (venue: ' + venue + ').')

const finderResults = await parallel(
  buckets.map((bucket, idx) => () =>
    agent(finderPrompt(bucket), {
      label: 'finder: ' + (bucket.key || ('bucket ' + idx)),
      phase: 'Find',
      schema: FINDER_SCHEMA,
    })
  )
)

const rawFindings = finderResults
  .filter(Boolean)
  .flatMap((r) => (r && Array.isArray(r.findings)) ? r.findings : [])
  .filter(Boolean)

// Dedup on the bug's IDENTITY (normalized sink file:line), not its prose — so two
// finders describing the same bug with different wording don't both survive and become
// a self-dup SUBMISSION. Collapsed near-dups are logged (returned in `dropped`), never
// silently lost, so an over-collapse stays auditable.
const normSink = (s) => {
  const t = String(s || '').toLowerCase().replace(/\s+/g, '')
  const m = t.match(/[a-z0-9_./-]+:\d+/)   // a file:line token if the finder gave one
  return m ? m[0] : t
}
const seen = new Map()
const deduped = []
const collapsed = []
for (const f of rawFindings) {
  const key = normSink(f.sink)
  if (seen.has(key)) {
    collapsed.push({ finding: f, dropReason: 'in-code dup of ' + seen.get(key) + ' (same normalized sink ' + key + ')' })
    continue
  }
  seen.set(key, (f && f.id) ? f.id : ('#' + deduped.length))
  deduped.push(f)
}

log('Find: ' + rawFindings.length + ' raw finding(s); ' + deduped.length + ' after dedup; ' + collapsed.length + ' collapsed as in-code dup(s).')

if (deduped.length === 0) {
  log('No findings to grade — nothing cleared the Find phase. A clean skip is a success, not a failure.')
  return { survivors: [], dropped: [] }
}

// ---------------------------------------------------------------------------
// Phase 'Verify' — pipeline each finding (no barrier) through the three graders.
// Items flow independently: one can be in severity-recalibrate while another is
// still in source-verify. opts.phase is set on every stage agent so the no-barrier
// flow does not race on the global phase() state.
// ---------------------------------------------------------------------------
phase('Verify')
log('Verify: grading ' + deduped.length + ' finding(s) — source-verify (refute) -> dup-check -> severity-recalibrate.')

const graded = await pipeline(
  deduped,
  // (a) source-verify — refute and trace each link in repoPath.
  (prev, finding, idx) =>
    agent(sourceVerifyPrompt(finding), {
      label: 'source-verify: ' + finderId(finding, idx),
      phase: 'Verify',
      schema: VERIFY_SCHEMA,
    }).then((verify) => ({ finding: finding, verify: verify })),
  // (b) dup-check — Gate B. Short-circuit: a finding refuted at Gate A skips this agent
  // (and keeps the no-barrier latency win — this is a per-item skip, not a barrier).
  (prev, finding, idx) => {
    if (!prev || !prev.verify || prev.verify.verified !== true) return prev
    return agent(dupCheckPrompt(prev.finding), {
      label: 'dup-check: ' + finderId(finding, idx),
      phase: 'Verify',
      schema: DUP_SCHEMA,
    }).then((dup) => ({ finding: prev.finding, verify: prev.verify, dup: dup }))
  },
  // (c) severity-recalibrate — Gate C. Short-circuit: skip for a refuted or duplicate finding.
  (prev, finding, idx) => {
    if (!prev || !prev.verify || prev.verify.verified !== true) return prev
    if (!prev.dup || prev.dup.dup === true) return prev
    return agent(severityPrompt(prev), {
      label: 'recalibrate: ' + finderId(finding, idx),
      phase: 'Verify',
      schema: SEVERITY_SCHEMA,
    }).then((severity) => ({ finding: prev.finding, verify: prev.verify, dup: prev.dup, severity: severity }))
  },
)

// ---------------------------------------------------------------------------
// Keep only survivors: verified === true AND dup === false AND severity CRIT/HIGH/MED.
// Everything else is dropped WITH a reason (honest grading + an auditable journal).
// ---------------------------------------------------------------------------
const survivors = []
const dropped = []

// In-code dedup collapses are drops too — keep them auditable (not silently lost).
collapsed.forEach((c) => dropped.push({
  finding: c.finding, verify: null, dup: null, severity: null, dropReason: c.dropReason,
}))

// Account for any finding whose grading pipeline errored (a stage threw -> null),
// so nothing is silently lost from the tally.
graded.forEach((g, i) => {
  if (!g) {
    dropped.push({
      finding: deduped[i], verify: null, dup: null, severity: null,
      dropReason: 'grading pipeline errored on this finding (a stage threw); not gradable',
    })
  }
})

// Classify by the FIRST gate each finding failed (short-circuited findings carry only
// the stages that actually ran), so every drop records the true reason.
graded.filter(Boolean).forEach((g) => {
  // Gate A — refuted (dup-check + severity were short-circuited)
  if (!g.verify || g.verify.verified !== true) {
    dropped.push({
      finding: g.finding, verify: g.verify || null, dup: g.dup || null, severity: g.severity || null,
      dropReason: (g.verify && g.verify.brokenLink)
        ? ('source-verify refuted — broken link: ' + g.verify.brokenLink)
        : 'source-verify refuted — chain not proven (Gate A)',
    })
    return
  }
  // Gate B — duplicate, or dup-check agent unavailable (severity was short-circuited)
  if (!g.dup || g.dup.dup === true) {
    dropped.push({
      finding: g.finding, verify: g.verify, dup: g.dup || null, severity: g.severity || null,
      dropReason: g.dup ? ('duplicate — ' + (g.dup.evidence || 'prior art found'))
                        : 'dup-check unavailable (agent skipped or failed)',
    })
    return
  }
  // verified + non-dup: the severity agent should have run
  if (!g.severity) {
    dropped.push({
      finding: g.finding, verify: g.verify, dup: g.dup, severity: null,
      dropReason: 'incomplete grading — severity agent skipped or failed',
    })
    return
  }
  // Gate C — severity floor
  if (KEEP_SEVERITIES.indexOf(g.severity.severity) !== -1) {
    survivors.push(g)
    return
  }
  dropped.push({
    finding: g.finding, verify: g.verify, dup: g.dup, severity: g.severity,
    dropReason: 'recalibrated to ' + g.severity.severity + ' (below the MED default filing floor — log in PROGRESS; file only if this venue\'s rubric rewards Low/Info)',
  })
})

// Surface the overclaim tax — the gap between claimed and survived is the harness working.
const claimedHigh = deduped.filter((f) => f.claimedSeverity === 'CRIT' || f.claimedSeverity === 'HIGH').length
const survivedHigh = survivors.filter((g) => g.severity.severity === 'CRIT' || g.severity.severity === 'HIGH').length
log('Grading complete: ' + survivors.length + ' survivor(s), ' + dropped.length + ' dropped. ' +
    'Claimed CRIT/HIGH into the grader: ' + claimedHigh + '; survived at CRIT/HIGH: ' + survivedHigh + '. ' +
    'That gap is the overclaim tax — the harness working. A human files survivors and does lab validation.')

return { survivors: survivors, dropped: dropped }
