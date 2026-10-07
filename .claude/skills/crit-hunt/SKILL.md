---
name: crit-hunt
description: Harness for AUTHORIZED critical-vulnerability research and responsible disclosure through official programs only (huntr, ZDI, Google OSS VRP, vendor security-advisory programs). Use for bug-bounty source review and "crit hunting" of an in-scope open-source target - scope/scout a repo, design attack-surface buckets, fan out finder agents, and above all HONESTLY GRADE what they return - source-verify every link of the chain, dup-check advisories/PRs/issues, and recalibrate severity against the vendor's own precedent before a human files. Triggers on "crit hunt", "bug bounty source review", "find/triage vulnerabilities in <repo>", "is this a real bug or inflated severity", "grade / dup-check / severity-recalibrate this finding", "attack surface map", "deserialization sink review".
---

# crit-hunt

A Claude-Code-native runbook for **authorized** critical-vulnerability research and **responsible disclosure**. It organizes source review of in-scope open-source targets to find logic / bounds / authz / deserialization bugs, then **grades them honestly** before a human files them through the vendor's official channel.

**Honest grading is the heart of this tool.** Automated finders systematically overclaim severity - in the research this harness was built from, roughly **4-of-4 and 5-of-6 agent CRIT claims were overclaimed**. The harness exists to *catch* that. Value is created in verification, not in finding. Be default-skeptical of every CRIT claim, including your own.

> Paths below are relative to the **project root**. Read **strategy/STRATEGY.md** before a first run - it holds the deep rationale behind every step here. Keep a per-target journal from **templates/PROGRESS.md**; produce one write-up per survivor from **templates/SUBMISSION.md**; orchestrate the finder fan-out with **.claude/workflows/crit-hunt.js**.

---

## Red lines (non-negotiable)

- **Authorized, in-scope only.** Public bug-bounty programs, or systems the hunter owns/operates. Confirm scope *before* hunting. No non-consenting targets, no mass-targeting, no probing of live/production systems, no malicious use. If scope cannot be confirmed, stop.
- **Responsible disclosure only**, via the vendor's official program (huntr / ZDI / Google OSS VRP / the vendor's own advisory process). A **human files**; this harness only prepares the report.
- **Honor the carve-outs.** Respect the vendor's published threat model and trust-boundary exclusions. Attack *around* the carve-outs, never report *into* them.
- **Source review, not exploitation.** Report the **chain**. No working or weaponized exploit code and no live validation against anyone's systems - a non-functional *trigger outline* for the human's authorized lab is fine, a running PoC is not. Leave exploit development and lab validation to the human.
- **Never inflate.** A dup, documented/intended behavior, or an out-of-scope "finding" is **not a finding**. Honest grading beats volume every time.

---

## Pipeline at a glance (stages 0-5)

| # | Stage | Output |
|---|-------|--------|
| 0 | Target & venue selection | A target + venue decision, with the **threat model and carve-outs** recorded in PROGRESS.md |
| 1 | Scope & scout | A **surface map** + 90-day **churn ranking** (freshest = least-swept) |
| 2 | Bucket design | Attack surface split into churn-informed **buckets**, one crit hypothesis seed each |
| 3 | Fan-out finders | One finder per bucket, each carrying the **FINDER-PROMPT** |
| 4 | Honest grading | Finder output run through the **HONEST-GRADING checklist**; only survivors kept |
| 5 | Write-up & journal | One **SUBMISSION** per survivor; the **PROGRESS** journal updated |

---

## Stage 0 - Target & venue selection

1. **Relax the "elite-audited flagship" constraint.** Flagship projects with heavy recent maintainer activity are swarmed: dup risk is high and regressions are patched within days. Pure source review rarely yields crits there (the *flagship-hardening ceiling*). Prefer less-swept surface: smaller in-scope projects, and - within any target - new subsystems, new routers/connectors, and confidential-computing code.
2. **Pick the venue first, then read its rules.** Before hunting, open the program/venue page and the repo's `SECURITY.md` / security docs. Extract three things: (a) what is **in scope**, (b) the **severity rubric**, (c) the **threat model and carve-outs** (what the vendor explicitly declines - e.g. "loading untrusted model files is out of scope", "local attacker with root is not a boundary").
3. **Record the carve-outs verbatim** in the target's PROGRESS.md. Every later phase filters against them. A chain that lands inside a carve-out is dead on arrival.

---

## Stage 1 - Scope & scout

1. **Clone light.** For big repos use a blobless + sparse checkout so you only pull the surface you'll review: `scripts/clone.sh <repo-url> <dest> [subpath ...]`. Pin and record the exact `sha` - every file:line you later cite must be true at that `sha`.
2. **Find the freshest surface.** Run `scripts/churn.sh --days 90 [path]` to rank files/dirs by recent change. The hottest, least-swept code is where crits hide. Also flag **incomplete-fix siblings**: when a security patch just landed, is there a *parallel* path it missed?
3. **Build a surface map.** Enumerate entry points and trust boundaries - where untrusted input enters (network endpoints, IPC, parsed files, message queues, guest->host for VMM/kernel targets) and what privilege each entry assumes. Reachability recipes below (`scripts/*.sh`) seed this map fast.
4. Write the surface map + churn ranking into PROGRESS.md.

---

## Stage 2 - Bucket design

1. **Decompose the surface into buckets**, churn-informed - give the hottest surface its own bucket. A bucket is a coherent slice one finder can own end-to-end.
2. Use the reference taxonomies:
   - **Web / app backend:** authz/RBAC gates, server-side code-exec sinks, unsafe deserialization, template injection (SSTI), unauth endpoints, SSRF.
   - **Native / VMM (e.g. device emulators):** per-device / per-subsystem; bounds / state-machine / use-after-free; tag each with a **reachability tier** (guest-unprivileged vs guest-root; network-reachable?).
   - **Kernel / hypervisor:** per-subsystem; guest-reachability; confidential-computing paths.
3. **Seed one specific crit hypothesis per bucket.** A recurring high-severity vein worth seeding where it applies: **deserialization over a network-reachable channel** (`pickle` / `recv_pyobj` / `torch.load` and friends) in ML-serving frameworks. Seed hypotheses around the *carve-outs*, not into them.

---

## Stage 3 - Fan-out finders

Spin up **one finder per bucket**. Orchestrate the fan-out with `.claude/workflows/crit-hunt.js` (it spawns a subagent per bucket and collects their chains), or spawn them by hand. Hand each finder the template below, filled in for its bucket. **Finders report chains, not exploits.**

### FINDER-PROMPT (copy, fill the `<...>`, hand to each finder)

```text
ROLE: You are a FINDER for bucket <BUCKET NAME>. Source-review ONLY. You find and
PROVE reachable bug chains. You do not write or run exploits.

TARGET: <owner/repo @ sha>   (local path: <path>)

THREAT-MODEL FILTER (from the venue's SECURITY.md / program scope):
  IN SCOPE: <...>
  CARVE-OUTS / OUT OF SCOPE (never report into these): <...>
  SEVERITY RUBRIC: <link or 1-line summary of how THIS vendor rates things>

HYPOTHESIS (one crit, specific - not "look for bugs"):
  <e.g. "An unauthenticated network request to <new router> reaches a deserialization
   sink with attacker-controlled bytes under default config.">

REACHABILITY BAR (a candidate only counts if it clears ALL of this):
  - Trigger actor: <unauth network client | authenticated low-priv user |
                    guest-unprivileged | guest-root | local user | ...>
  - Entry channel: <network endpoint | IPC | file parsed on open | queue msg | ...>
  - Precondition budget: <default config? needs a non-default flag? feature-gated?>
  A bug sitting behind an auth gate, or inside a venue carve-out, does NOT clear the
  bar - drop it. Downgrade for every extra precondition.

DUP-CHECK DUTY (FLAG, do not self-clear — Gate B at stage 4 is authoritative):
  - Quick-scan for prior art on this sink / flow / component: CVE / GHSA / NVD +
    the vendor's own advisories, and in-flight work (merged PRs, OPEN PRs, OPEN
    issues - grep the sink symbol and the file path).
  - Incomplete-fix check: if a sibling was just patched, is THIS the unpatched
    remainder (novel) or the same path (likely dup)?
  - FLAG a likely dup with its link; do NOT drop it yourself and never self-file.
    The grading pass confirms. (Mechanics: scripts/dup-check-notes.md.)

OUTPUT - REPORT THE CHAIN, NOT AN EXPLOIT. For each survivor give:
  - source -> transform(s) -> sink as file:line hops (cite REAL lines at the pinned
    sha; no exploit payloads, no PoC)
  - the untrusted input, and the guard(s) that fail to stop it
  - reachability evidence: how the trigger actor reaches the entry channel
  - self-assessed severity WITH the vendor-precedent comparison you used to pick it
  - dup-check results: what you searched, what you found
  If you cannot source-verify a hop, SAY SO and downgrade it to a "lead". Default-
  skeptical: when unsure between two severities, pick the lower.
```

---

## Stage 4 - Honest grading (the heart)

Run every finder output through the gates below, **in order**. A finding that fails a gate is dropped or downgraded - it does not proceed. Grade as the adversary of the finder, not its advocate.

### HONEST-GRADING checklist

```text
GATE A - SOURCE-VERIFY EVERY LINK (trust no finder prose):
  [ ] Open every file:line hop yourself at the pinned sha. Source, each transform,
      each guard, the sink - all real, all current.
  [ ] Confirm untrusted input ACTUALLY reaches the sink (no validation / escaping /
      type check the finder skipped over).
  [ ] Confirm the "missing" guard is really missing - not present on a parent, caller,
      decorator, middleware, or config default.
  [ ] Any hop you cannot verify => chain NOT proven. Demote to "lead", do not submit.

GATE B - DUP-CHECK (refuse dups):
  [ ] Published: CVE / GHSA / NVD + vendor advisories for this sink/flow/component.
  [ ] In-flight: merged PRs, OPEN PRs, OPEN issues (search the sink symbol + file).
  [ ] Incomplete-fix: sibling just patched? Is this the unpatched remainder (keep) or
      the same path (drop)?
  [ ] Any covering hit => DUP. Drop. Never file a dup.
  (Mechanics + exact gh/MCP queries: scripts/dup-check-notes.md.)

GATE C - SEVERITY-RECALIBRATE vs VENDOR PRECEDENT (refuse inflation):
  [ ] Pull the venue's rubric + 3-5 of the VENDOR'S OWN past ratings for similar bugs.
  [ ] Re-score against THAT precedent - not your prior, not CVSS-on-autopilot.
  [ ] Carve-out test: does the published threat model already exclude this actor or
      channel? If yes => not a vuln here. Drop.
  [ ] Documented-behavior test: is this intended/documented (a known flag, a "don't
      load untrusted X" footgun)? If yes => drop.
  [ ] Reachability tax: downgrade for every precondition (auth, non-default flag,
      local-only, needs-root, needs-a-second-bug).

ANTI-OVERCLAIM RULES (the overclaim tax is real - ~4/4 and 5/6 CRIT claims inflated):
  - CRIT requires ALL of: unauth-or-low-priv trigger + network-or-equivalent reach +
    serious impact (RCE / auth-bypass / memory corruption) + default config. Missing
    any one => it is not a CRIT.
  - "Could be chained to X" with X's links unproven => NOT the severity of X.
  - Theoretical / needs-attacker-already-privileged / needs-a-second-unproven-bug =>
    downgrade hard.
  - Tie between two ratings => pick the LOWER and write down why.
  - SURVIVORS ONLY: a finding that clears A, B, and C becomes a SUBMISSION. Everything
    else is a logged lead, not a submission.
```

**Track the overclaim tax.** In PROGRESS.md record, per bucket, *claimed CRIT/HIGH* vs *survived*. That ratio is the harness working - surface it, don't bury it.

**Illustrative chain format** (fictional names - never copy real target source):

```text
# ILLUSTRATIVE ONLY
unauth source:  net/router.py:88     POST /v1/load accepts raw body, no auth decorator
  -> transform: serde/frame.py:40    body passed to loader without a type check
  -> SINK:      serde/pickle.py:12    pickle.loads() on attacker-controlled bytes
guard that fails: auth decorator present on /v1/admin/* but absent on /v1/load
trigger actor:   unauthenticated network client, default config  => clears the bar
```

---

## Stage 5 - Write-up & journal

1. **One SUBMISSION per survivor.** Copy **templates/SUBMISSION.md** and fill it: the chain as file:line hops, the untrusted input and failing guard, reachability, the vendor-precedent severity justification, and the dup-check record. No exploit code. This is the artifact a human reviews and files through the official channel.
2. **Keep the PROGRESS journal.** Copy **templates/PROGRESS.md** once per target and update it through every phase: target+venue decision, recorded carve-outs, surface map, buckets, finder results, grading outcomes (including drops and *why*), the overclaim tally, and dup hits. The journal is how a run is auditable and resumable.

---

## Reachability recipes (`scripts/*.sh`)

Fast census tools to seed the surface map (Stage 1), sharpen buckets (Stage 2), and give finders a reachability starting point (Stage 3). Treat output as *leads to source-verify*, never as proof.

- **Authz-gate census** - `scripts/authz-census.sh <path>`: lists every route/handler and the auth/RBAC gate (decorator, middleware, guard) attached to its own block. Use it to spot handlers the gate *forgot*.
- **Unauth-endpoint census** - `ONLY_NONE=1 scripts/authz-census.sh <path>`: the subset whose guard column comes back blank - the unauth / missing-gate leads, the highest-value entry channel. A blank guard is a prompt to READ THE CODE (a router/global/mixin gate may still cover it), never a finding on its own. Cross-check new/churned routers here first.
- **Sink grep** - `scripts/sink-grep.sh <path>`: greps for dangerous sinks (deserialization `pickle`/`recv_pyobj`/`torch.load`, command/`exec`, template render/SSTI, raw memcpy/length math for native targets). Each hit is one end of a candidate chain - the finder's job is to connect it back to an untrusted source.

---

## Where crits actually hide (why these steps)

- The **newest / least-swept** surface: new routers, new connectors, confidential-computing code.
- **Unauth endpoints**, and auth gates with a forgotten handler.
- **Incomplete-fix siblings** of a just-patched CVE - the path the fix missed.
- **Deserialization over a network-reachable channel** - a recurring high-severity vein in ML-serving frameworks.
- Vendors fence their trust boundaries with public docs; the room is *around* the carve-outs. Full rationale and worked reasoning: **strategy/STRATEGY.md**.

---

## References

- **strategy/STRATEGY.md** - the thinking behind this runbook (read first).
- **templates/PROGRESS.md** - per-target journal (one per target).
- **templates/SUBMISSION.md** - per-survivor write-up (one per filed finding).
- **.claude/workflows/crit-hunt.js** - finder fan-out orchestration.
- **scripts/clone.sh**, **scripts/churn.sh**, **scripts/authz-census.sh**, **scripts/sink-grep.sh** - scope/scout and reachability census tools.
- **scripts/dup-check-notes.md** - the dup-check (Gate B) playbook.
