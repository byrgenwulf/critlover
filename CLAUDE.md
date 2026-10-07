# critlover — operating context

critlover is a reusable harness for **authorized** critical-vulnerability research and **responsible
disclosure** through official programs only (huntr, ZDI, Google OSS VRP, vendor GHSA / `SECURITY.md`).
If you are working *in this repo* you are either (a) running a hunt — start at
[`.claude/skills/crit-hunt/SKILL.md`](.claude/skills/crit-hunt/SKILL.md) (`/crit-hunt`) — or (b)
developing the harness itself. Either way, the rules below hold.

## Non-negotiable ethos
- **Authorized, in-scope targets only.** Public bounty programs or the hunter's own systems. No
  non-consenting targets, no mass-targeting, no malicious use.
- **Responsible disclosure.** Honor the vendor's published threat model and trust-boundary carve-outs —
  attack *around* them, never report *into* accepted behavior.
- **Honest grading is the point.** Finders overclaim; verification creates the value. Never file a dup,
  documented behavior, or an inflated severity. Report the **chain**, not an exploit — no working PoC,
  no payloads. A human validates and files.

## Canon (keep every file consistent with this)
- One pipeline, **stages 0–5** (the word is "stage"; "phase" is reserved for the workflow's `phase()`
  groups): target & venue → scope & scout → bucket design → fan-out finders → honest grading → write-up.
- Honest grading = **three gates**: **A** source-verify · **B** dup-check · **C** severity-recalibrate
  (the carve-out test is folded into C).
- **Consolidated artifacts:** stages 0–3 are sections of `templates/PROGRESS.md`; the only standalone
  templates are `PROGRESS.md` and `SUBMISSION.md`.
- **MED is the default filing floor;** a sub-MED result is logged in `PROGRESS.md`, not filed, unless the
  venue's rubric explicitly rewards a Low/Info.
- The four veins where crits hide: newest/least-swept surface; unauth/pre-auth endpoints; incomplete-fix
  siblings of a just-patched CVE; network-reachable deserialization.

## Layout
- `.claude/skills/crit-hunt/SKILL.md` — operator playbook · `.claude/workflows/crit-hunt.js` — fan-out + 3-gate grading
- `strategy/STRATEGY.md` — doctrine (§1–§6) · `playbooks/` — per-target-class playbooks
- `templates/` — PROGRESS + SUBMISSION · `scripts/` — read-only recon · `examples/` — a worked example · `tests/` — script self-tests

When editing, preserve the canon above; the docs cross-reference each other by path.
