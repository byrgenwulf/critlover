# critlover

A reusable, Claude-Code-native harness for **authorized** critical-vulnerability research
and **responsible disclosure through official channels only**.

## What it is

critlover organizes systematic **source review** of open-source projects to find high-impact
logic, bounds, authorization, and deserialization bugs — then grades them honestly before a
human files them. It decomposes a target's attack surface into "buckets", fans out one *finder*
agent per bucket (each carrying the vendor's threat model, a specific crit hypothesis, and a
reachability bar), and then spends the bulk of its effort on the step that actually creates value:
**verification**. Finders systematically overclaim severity, so the harness is built to catch that
— source-verifying every link of a chain, dup-checking against published advisories and open
PRs/issues, and re-scoring against the vendor's *own* severity precedent — and keeps only the
survivors. It reports the chain and leaves live exploit development and lab validation to the human.

---

## Authorized use and responsible disclosure only

> This harness is for security research **you are authorized to perform**, disclosed **responsibly**
> through the vendor's official program. It is not for attacking systems you do not own or have not
> been invited to test.

**Three non-negotiables. Every file in this repo reflects them; so must every run.**

1. **Authorized, in-scope targets only.** Public bug-bounty programs, or the hunter's own systems.
   No non-consenting targets. No mass-targeting. No malicious use.
2. **Responsible disclosure via the vendor's official program.** File through the proper channel —
   [huntr](https://huntr.com), [ZDI](https://www.zerodayinitiative.com),
   [Google OSS VRP](https://bughunters.google.com/about/rules/open-source), or the vendor's own
   security-advisory program (e.g. GitHub Security Advisories / `SECURITY.md`). **Honor the vendor's
   published threat model and trust-boundary carve-outs** — attack *around* the carve-outs, never
   into documented, accepted behavior.
3. **Honest grading is the point.** Never file a duplicate, documented behavior, or an inflated
   severity. A skipped non-finding is a success, not a failure.

critlover produces **write-ups for a human to review and file**. It does not auto-submit, and it
does not develop or run working exploits. Full doctrine lives in
[`strategy/STRATEGY.md`](strategy/STRATEGY.md); the operator checklist lives in
[`.claude/skills/crit-hunt/SKILL.md`](.claude/skills/crit-hunt/SKILL.md).

---

## Repository layout

```
critlover/
├── README.md                          ← you are here
├── CLAUDE.md                          operating context + canon for anyone working in this repo
├── .claude/
│   ├── skills/crit-hunt/SKILL.md       operator-facing playbook — invoke with /crit-hunt
│   └── workflows/crit-hunt.js          fan-out / fan-in orchestration for the pipeline
├── strategy/
│   └── STRATEGY.md                     the doctrine: where crits hide, carve-outs, the overclaim tax
├── playbooks/                          per-target-class playbooks (pick one at stage 0)
│   ├── README.md                       index + how to add a playbook
│   ├── ml-serving.md                   ML-serving / LLM-inference frameworks (Python/FastAPI/RPC)
│   ├── vmm-devices.md                  VMM / device emulators (C; QEMU-style, userspace models)
│   └── kvm-kernel.md                   in-kernel KVM hypervisor + distributed-serving control planes
├── templates/                          the two fill-in artifacts (stages 0–3 live as sections of PROGRESS.md)
│   ├── PROGRESS.md                     per-target journal — run card, buckets, round ledger, per-lead reasoning
│   └── SUBMISSION.md                   one per survivor, ready for a human to review and file
├── examples/                          a fictional worked hunt, end to end
│   ├── EXAMPLE-progress.md             filled-in journal (what "good" looks like)
│   └── EXAMPLE-submission.md           filled-in survivor write-up
├── scripts/                           read-only recon helpers (no judgment, just data)
│   ├── clone.sh                        blobless + sparse clone for large repos
│   ├── churn.sh                        90-day churn analysis → freshest (least-swept) surface
│   ├── entrypoints.sh                  entry-point census by channel (listeners/routes/rpc/mq/…)
│   ├── sink-grep.sh                    dangerous-sink census (deser / exec / SSTI / native), by class
│   ├── authz-census.sh                 route-to-guard table (ONLY_NONE=1 → unauth / missing-gate subset)
│   ├── patch-variant.sh                incomplete-fix / variant analysis from a fix commit
│   ├── dup-scan.sh                     Gate B dup-check enumeration (advisories + PRs + issues)
│   └── dup-check-notes.md              the dup-check playbook (judgment behind dup-scan.sh)
├── tests/                             self-tests for the recon scripts (synthetic fixtures)
│   └── run.sh                          bash tests/run.sh → PASS/FAIL/SKIP per check
└── .github/workflows/ci.yml           CI hard gates: bash -n + the self-test suite · shellcheck (pinned v0.10.0, --severity=style)
```

- **Skill** — [`.claude/skills/crit-hunt/SKILL.md`](.claude/skills/crit-hunt/SKILL.md):
  the step-by-step operator playbook. Start here; it drives the whole pipeline.
- **Workflow** — [`.claude/workflows/crit-hunt.js`](.claude/workflows/crit-hunt.js):
  the orchestration that fans out one finder per bucket and fans their claims back in for grading.
- **Strategy** — [`strategy/STRATEGY.md`](strategy/STRATEGY.md): the reasoning behind the moves —
  bucket taxonomies, the flagship-hardening ceiling, carve-out tactics, and the overclaim tax.
- **Playbooks** — [`playbooks/`](playbooks/): per-target-class guides (ML-serving, VMM/device,
  KVM/kernel) — the buckets, sinks, and carve-outs to expect for a given kind of target. Pick one at
  stage 0 and let it specialize the pipeline.
- **Templates** — [`templates/`](templates/): two fixed shapes — a per-target
  [`PROGRESS.md`](templates/PROGRESS.md) journal (stages 0–3 as sections) and one
  [`SUBMISSION.md`](templates/SUBMISSION.md) per survivor — so output is comparable across runs.
- **Examples** — [`examples/`](examples/): one fictional hunt filled in end to end, so you can see what a
  good PROGRESS journal and SUBMISSION look like before running your own.
- **Scripts** — [`scripts/`](scripts/): the read-only plumbing (clone, churn, entrypoint + sink + authz
  census, incomplete-fix variant analysis, dup-check) the skill and workflow lean on so agents spend
  their tokens on judgment, not recon. Self-tested by [`tests/run.sh`](tests/run.sh).

---

## Quickstart

critlover runs one **canonical pipeline** (stages 0–5). The shared vocabulary below is used
identically across the skill, workflow, strategy, and templates. The one-command path is to invoke
the skill and let it drive; the stages show what happens under the hood.

**One-command path:** open the target repo in Claude Code and run `/crit-hunt` — the skill
([`.claude/skills/crit-hunt/SKILL.md`](.claude/skills/crit-hunt/SKILL.md)) walks you through every
stage, calling the scripts and the workflow for you.

**The stages, by hand:**

**0 · Target and venue selection.** Relax the "elite-audited flagship" constraint (those are swarmed;
dup risk is high). Pick the venue *first*, then **read its severity rubric and the project's threat
model** (`SECURITY.md` / security docs) before hunting. Record scope and carve-outs in the run card
and threat-model-filter block of [`templates/PROGRESS.md`](templates/PROGRESS.md).

**1 · Scope and scout.** For a large target, clone cheaply:

```sh
scripts/clone.sh <repo-url> <dest> [subpath ...]   # blobless + sparse
scripts/churn.sh <dest> 90                          # rank dirs/files by recent change → freshest surface
```

Capture the result as the surface-map section of [`templates/PROGRESS.md`](templates/PROGRESS.md).
Crits hide in the **newest, least-swept** code (new routers, new connectors, confidential-computing
paths) and in the incomplete-fix siblings of a just-patched CVE.

**2 · Bucket design.** Decompose the attack surface into churn-informed **buckets** (one row each in
the buckets table of [`templates/PROGRESS.md`](templates/PROGRESS.md)). Pick the taxonomy that fits the
target (web/app backend; native/VMM; kernel/hypervisor) from [`strategy/STRATEGY.md`](strategy/STRATEGY.md).

**3 · Fan-out finders.** Run the workflow:

```sh
# via the skill, or directly through the Claude Code workflow runner:
.claude/workflows/crit-hunt.js
```

It spawns **one finder per bucket**, each handed the **FINDER-PROMPT** from the skill: the **vendor
threat-model filter**, a **specific crit hypothesis**, a **reachability bar** (who can trigger it —
network-reachable? guest-unprivileged vs guest-root?), and a **dup-check duty** (finders *flag* likely
prior art; the authoritative call is Gate B at stage 4).

**4 · Honest grading.** The workflow's **Verify** phase automates this (or do it by hand), for each
claim in order — the **three gates**: **A · source-verify** every link of the chain → **B · dup-check**
([`scripts/dup-check-notes.md`](scripts/dup-check-notes.md)) against published advisories, open PRs, and
open issues → **C · recalibrate severity** against the vendor's own precedent (carve-out test folded in)
→ **keep only survivors**. Be default-skeptical of every CRIT claim.

**5 · Write-up and journal.** One [`templates/SUBMISSION.md`](templates/SUBMISSION.md) per survivor
(the chain, reachability, the dup-check trail, a calibrated severity with its justification) for a
human to review and file through the official channel. Keep a per-target
[`templates/PROGRESS.md`](templates/PROGRESS.md) journal — buckets explored, claims made, and
*why each one was skipped or survived*.

---

## Philosophy: honest grading

The hard part of crit hunting is not finding candidates — automated finders produce plenty. The hard
part is admitting which ones are real. In the research this harness was built from, roughly **four of
four and five of six** agent "CRIT" claims were overclaimed: inflated severity, documented behavior
mistaken for a bug, an unreachable sink, or a silent duplicate of something already filed. That gap is
the **overclaim tax**, and paying it down — by source-verifying every link, dup-checking honestly, and
re-scoring against the vendor's own precedent — is where the value is actually created.

So critlover is built to be **default-skeptical of its own output**. The reward is not a long list of
findings; it is a short list you can stake your name on. A finding you *correctly discard* is a win: it
protects the venue's signal-to-noise, respects the maintainers' time, and keeps the hunter's reputation
intact. File only what survives — never a dup, never documented behavior, never an inflated score.
