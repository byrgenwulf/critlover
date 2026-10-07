# [`<SEVERITY: CRIT | HIGH | MED | LOW | INFO>`] `<component>` — `<bug class>` — `<one-line impact>`

*One per survivor — a finding that cleared all three grading gates (source-verify, dup-check,
severity-recalibrate). This is the artifact a human reviews and files.*

> **For responsible disclosure to `<VENUE>`'s official program only.** Authorized, in-scope target.
> This is a **source-review report: a verified chain, not a weaponized exploit.** No working PoC, no
> payload bytes. A human lab-reproduces and files. Do not run anything here against systems you do not
> own or are not invited to test.

---

## At a glance

| Field | Value |
|---|---|
| Target | `<owner/repo>` |
| Commit (HEAD) | `<full 40-char sha>` — every `file:line` below is true at this sha |
| Component / subsystem | `<path or subsystem>` |
| Bug class | `<CWE-### : e.g. Deserialization of Untrusted Data>` |
| **Severity (vendor rubric)** | **`<SEVERITY>`** — `<vendor tier name / CVSS if the rubric uses it>` |
| Attacker tier | `<unauth network client | authenticated low-priv user | guest-unprivileged | guest-root | local user>` |
| Venue | `<huntr | ZDI | Google OSS VRP | vendor GHSA>` · rubric `<link>` |
| Status | `<draft | ready-for-human-review | filed: <report id/link>>` |

## Preconditions

*Each precondition is a severity tax — list every one honestly; the reader subtracts.*

- **Config:** `<default config? which non-default flag / feature-gate is required?>`
- **Deployment:** `<network-exposed by default? behind a proxy? which listener/port?>`
- **Prior access / privilege:** `<none | authenticated | on-the-cluster | guest-root | ...>`
- **Other bugs needed to chain:** `<none — self-contained | needs <unproven?> second bug>`

## Summary

`<2–4 plain sentences, no adjectives: what the bug is, who can trigger it over what channel, and
what it yields (RCE / auth-bypass / memory corruption / info-leak). State the single sentence that
makes it a `<SEVERITY>` under the vendor's own rubric.>`

## Source chain (verified at the pinned commit)

*Every hop is a real `file:line` at `<sha>`, opened and confirmed during grading (Gate A). Shapes
below are illustrative placeholders — fill with the true hops; do not paste real source verbatim.*

```text
SOURCE   <path>:<line>   <untrusted input enters — endpoint / IPC / parsed-on-open file / queue msg / guest I/O>
 → GUARD <path>:<line>   <the check that SHOULD stop it — absent here, or present only on a sibling/parent>
 → XFORM <path>:<line>   <passed onward without a type/length/escape check>
 → SINK  <path>:<line>   <the dangerous operation: pickle.loads / exec / render / memcpy / length math>
```

- **Untrusted input:** `<what the attacker controls, and its format>`
- **Failing / absent guard:** `<the specific check that is missing — and confirmation it is NOT present
  on a caller, decorator, middleware, parent router, or config default>`
- **Why it reaches the sink:** `<the unbroken data path from source to sink>`

## Reachability + attacker tier

- **Trigger actor:** `<...>` *(the lower the privilege, the higher the severity)*
- **Entry channel:** `<network endpoint | IPC | file parsed on open | message queue | guest→host | ...>`
- **Path to the channel:** `<how the actor reaches it — route is registered / listener binds / no auth decorator>`
- **Reachability evidence (`file:line`):** `<route table / listener setup / the missing-gate line>`
- **CRIT-bar check:** a CRIT needs **all** of — unauth-or-low-priv trigger · network-or-equivalent
  reach · serious impact (RCE / auth-bypass / memory corruption) · default config.
  `<which legs this clears; if any leg is missing, it is NOT a CRIT — say so and drop the tier>`

## Trigger / reproduction outline — no working PoC

*The **shape** of a request/command that would exercise the path — so a human can reproduce it in an
authorized lab. **No working exploit, no payload bytes, no shellcode, no gadget chain.** Building and
running a real PoC is the validation lane (below), not this report.*

```text
# OUTLINE — illustrative, non-functional
<method / command>        e.g. POST <endpoint>   (or: send <message type> on <channel>)
<auth state>              e.g. no credentials / low-priv token
<body / arg shape>        a <format> object whose <field> targets the <sink> — PAYLOAD INTENTIONALLY OMITTED
Observable success signal <what the human watches for: process crash / out-of-band callback /
                           auth-state change / unexpected deserialized object>
```

## Dup-check evidence (Gate B)

*Done before filing — a dup is worth zero and costs credibility. Record what was searched, not just the verdict.*

| Source | Query / symbol searched | Result | Link |
|---|---|---|---|
| CVE / NVD | `<sink symbol, component>` | `<none | hit>` | `<...>` |
| GHSA + vendor advisories | `<...>` | `<...>` | `<...>` |
| Merged PRs | `<sink symbol + path>` | `<...>` | `<...>` |
| **OPEN** PRs | `<...>` | `<...>` | `<...>` |
| **OPEN** issues | `<...>` | `<...>` | `<...>` |
| Incomplete-fix check | `<sibling CVE/patch>` | `<this is the UNPATCHED remainder (novel) | the same path (dup)>` | `<...>` |

**Conclusion:** `<NOVEL — no covering hit>` *or* `<DUP — do not file, see <link>>`

## Severity justification — scored against the VENDOR'S rubric

*Score against the vendor's own precedent, not a prior and not CVSS-on-autopilot.*

- **Venue rubric:** `<link>` · **tier claimed:** **`<SEVERITY>`**
- **Vendor precedent (3–5 of their OWN past ratings for similar bugs):**
  - `<CVE/GHSA>` — `<similar bug>` — rated `<tier>`
  - `<CVE/GHSA>` — `<...>` — rated `<tier>`
  - `<...>`
- **Mapping to the rubric:** `<why this lands at <SEVERITY> per THEIR criteria>`
- **Carve-out test:** `<no documented carve-out excludes this actor/channel — OR, if one caps it, the
  honest capped severity and the verbatim carve-out it hits>`
- **Documented-behavior test:** `<not an intended/documented footgun (e.g. a "don't load untrusted X" note)>`
- **Reachability tax applied:** `<each precondition that pulled the score down>`
- **Tie-break:** `<when between two tiers, chose the lower because <reason>>`

## Lane split

**Reporter lane — source review (DONE in this report).** Verified source chain, reachability argument,
dup-check trail, and vendor-precedent severity above. No exploit built, no system touched.

**Validation lane — human (TO DO before / at filing).** Lab-reproduce in an **authorized** environment,
develop and run any working PoC there, confirm the severity holds, then file through `<VENUE>`'s official
channel. Do not validate against non-consenting or production systems.

---

*Prepared by critlover source review. File only if it survived all three gates (A source-verify ·
B dup-check · C severity-recalibrate). **MED is the default filing floor** — a finding recalibrated
below MED is normally logged in PROGRESS.md, not filed; file a LOW/INFO only where the venue's rubric
explicitly rewards it. Never file a dup, documented behavior, or an inflated severity — the short list
you can stake your name on is the product.*
