# critlover — PROGRESS: `<owner/repo>`

*Per-target hunting journal. One per target. The running record that makes a hunt auditable and
resumable — it carries the live ledger and the per-lead reasoning. Stages 0–3 are recorded in its own
sections below (run card, threat-model filter, clone/scope notes, buckets table); the per-bucket finder
charter is the FINDER-PROMPT in the skill, and the only other template is `SUBMISSION.md`, one per
survivor.*

> **Authorized, in-scope target only.** Responsible disclosure via `<VENUE>`'s official program only.
> This is **source review** — a human validates in a lab and files. **Honest grading over volume:**
> a correctly discarded finding is a win. Never file a dup, documented behavior, or an inflated severity.

---

## Run card (stage 0–1 header)

| Field | Value |
|---|---|
| Target | `<owner/repo>` |
| HEAD | `<40-char sha>` — **pinned**; every `file:line` in this file is true at this sha |
| Venue | `<huntr | ZDI | Google OSS VRP | vendor GHSA / SECURITY.md>` |
| Severity rubric | `<link to the venue's rubric>` — read it; never score from memory |
| Scope / `SECURITY.md` | `<link>` |
| Operator | `<handle>` · Started `<date>` · Status `<active | paused | closed>` |
| Carve-outs | recorded verbatim in the threat-model-filter block below |

**Threat-model filter (summary).** *Carry this into every finder (stage 3) and every grade (stage 4).*
- **In scope:** `<...>`
- **Carve-outs — never report into these (recorded verbatim):**
  - `<"inter-node channel is insecure by default; run on a trusted network" — verbatim>`
  - `<"device model X is a convenience emulation, not a security boundary" — verbatim>`
  - `<...>`
- **Severity rubric, 1-line:** `<how THIS vendor rates things>`

**Clone / scope notes.**
- Clone: `<blobless + sparse? subpaths pulled>` · Churn window: `<e.g. churn.sh --days 90>`
- Freshest / least-swept surface (hunt first): `<top churned dirs/files>`
- Incomplete-fix watch: `<just-patched CVE/PR, and the sibling path to check>`
- Pre-auth / unauth entry surface: `<endpoints reachable before authentication>`

**Buckets (stage 2).** *One finder owns each; taxonomy = `<web/app | native/VMM | kernel/hypervisor>`.*

| # | Bucket | Churn rank | Seeded crit hypothesis (one, specific) | Reachability tier |
|---|---|---|---|---|
| B1 | `<name>` | `<hot/med/cold>` | `<e.g. unauth request to new router reaches a deserialization sink>` | `<unauth-net | low-priv | guest-unpriv | guest-root>` |
| B2 | `<...>` | `<...>` | `<...>` | `<...>` |

---

## Round ledger (stages 3 → 4)

*One table per fan-out round. **finder verdict** = what the finder self-claimed. **my re-grade** = the
gate outcome after I source-verified + dup-checked (grade as the finder's adversary, not its advocate).
**severity** = final, vendor-calibrated. **status** = disposition.*

Legend — re-grade: `A✓/A✗` source-verify · `B✓/B✗` dup-check · `C:` recalibrate (`from→to`, reason).
Status: `SUBMISSION-<n>` · `LEAD` (unverified hop, logged not filed) · `DROP:dup` · `DROP:carve-out` ·
`DROP:documented` · `DROP:unreachable` · `DROP:unverified` · `DOWNGRADED`.

### Round 1 — fan-out `<date>` · buckets `<B1,B2,...>`

| bucket | finder verdict | my re-grade after verify + dup-check | severity | status |
|---|---|---|---|---|
| `<B1>` | `<CRIT: RCE via pickle>` | `<A✓ B✓ C: CRIT→HIGH (auth gate present, +1 precondition)>` | `<HIGH>` | `<SUBMISSION-1>` |
| `<B1>` | `<CRIT>` | `<B✗ dup — GHSA-xxxx-xxxx covers this path>` | `<n/a>` | `<DROP:dup>` |
| `<B2>` | `<HIGH>` | `<A✗ sink unreachable: guarded by middleware on parent router>` | `<n/a>` | `<DROP:unreachable>` |
| `<B3>` | `<CRIT>` | `<C: carve-out — vendor declares this device a non-boundary>` | `<info>` | `<DROP:carve-out>` |
| `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |

**Round 1 note:** `<survivors? dry? what the round taught; anything to re-seed next round>`

### Round 2 — fan-out `<date>` · buckets `<...>`

| bucket | finder verdict | my re-grade after verify + dup-check | severity | status |
|---|---|---|---|---|
| `<...>` | `<...>` | `<...>` | `<...>` | `<...>` |

---

## Overclaim tax tally

*The overclaim tax is the point of the harness — surface it, don't bury it. Per bucket: claimed
CRIT/HIGH vs what actually survived honest grading.*

| Bucket | Finder CRIT claims | Finder HIGH claims | Survived (any sev) | Filed |
|---|---|---|---|---|
| `<B1>` | `<2>` | `<1>` | `<1>` | `<1>` |
| `<B2>` | `<1>` | `<0>` | `<0>` | `<0>` |
| **Total** | `<n>` | `<n>` | `<n>` | `<n>` |

**Target overclaim ratio:** `<survived / claimed, e.g. 1/4 CRIT claims survived>`
`<one line — is the finder pattern matching the ~4/4 and 5/6 overclaim seen in the source research?>`

---

## Per-lead detail

*One block per notable claim (survivor or closed). The reasoning that the ledger row abbreviates.
Cite real `file:line` hops at the pinned sha; keep examples generic — no real source pasted, no PoC.*

### Lead `<B1-L1>` — `<short title>` — finder claimed `<CRIT>`

- **Chain (verified hops):**
  - source `<path>:<line>` — `<untrusted input enters>`
  - guard `<path>:<line>` — `<the check that should stop it — present? absent? on parent?>`
  - transform `<path>:<line>` — `<passed on without type check>`
  - **sink** `<path>:<line>` — `<deserialize / exec / memcpy / render>`
- **Reachability:** actor `<...>` · channel `<...>` · preconditions `<default? flag? second bug?>`
- **Verdict:** `<KEPT → SUBMISSION-1 at HIGH>` *or* `<CLOSED>` — `<why: which gate, what capped/killed it>`
- **Dup evidence:** `<searched CVE/GHSA/NVD + vendor advisories + merged/OPEN PRs + OPEN issues for
  `<sink symbol + path>`; result: novel / dup `<link>`; incomplete-fix check: `<unpatched remainder vs same path>`>`

### Lead `<B2-L1>` — `<short title>` — finder claimed `<...>`

- **Chain:** `<... file:line hops ...>`
- **Reachability:** `<...>`
- **Verdict:** `<CLOSED — DROP:carve-out — chain lands inside the "`<verbatim carve-out>`" exclusion>`
- **Dup evidence:** `<...>`

---

## Stop / pivot log

*Defaults (tune per target; record every decision here). Per bucket: retire after **N = 2** dry finder
passes. Per target: **pivot after K = 2** dry rounds (**K = 1** on a hardened flagship — if the first
honest round is dry, the ceiling is real; leave).*

| When | Decision | Why |
|---|---|---|
| `<round/date>` | `<retire B2 | re-run churn with new window | switch taxonomy | change venue | leave target>` | `<...>` |

---

## Final honest verdict

- **Rounds run:** `<n>` · **Buckets:** `<explored / retired>` · **Survivors filed:** `<n>` (`<SUBMISSION-x, ...>`)
- **Overclaim summary:** `<claimed vs survived; the tax paid this run>`
- **Why stopped / pivoted:** `<ceiling hit | survivors in hand | venue gap unfundable | out of surface>`
- **Residual leads for a future run:** `<unverified hops, newer churn to revisit, incomplete-fix siblings>`
- **One-line call:** `<e.g. "1 HIGH filed to <venue>; target retired at K=2 dry on the remaining buckets.">`
