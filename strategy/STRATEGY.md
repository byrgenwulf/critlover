# critlover — STRATEGY

**Why most flagship source-review hunts don't yield crits, and where crits actually hide.**

This is the doctrine behind the moves. The [README](../README.md) says *what* critlover does and the
skill (`.claude/skills/crit-hunt/SKILL.md`) says *how* to run a hunt step by step; this memo says *why* —
so an operator can decide what to hunt, where, and when to walk away. It uses the canonical pipeline's
shared vocabulary throughout: stages **0 · target & venue selection → 1 · scope & scout → 2 · bucket
design → 3 · fan-out finders → 4 · honest grading → 5 · write-up & journal**.

---

## The ethos *is* the strategy

The three non-negotiables are not a disclaimer bolted on top — they *are* the strategy, because each one
forecloses a whole class of moves and points at the ones that are left:

- **Authorized, in-scope targets only** — public bounty programs or your own systems; no non-consenting
  targets, no mass-targeting, no malicious use. → the hunt *starts* at venue selection, not at a repo. You
  pick a program whose scope you can satisfy, then hunt inside it.
- **Responsible disclosure, honoring the vendor's published threat model and carve-outs.** → you attack
  *around* the vendor's documented trust boundaries, never *into* accepted behavior. The carve-outs are a
  map of where not to waste budget.
- **Honest grading.** → you are default-skeptical of your own finders. The deliverable is a short list you
  can stake your name on, not a long list of maybes. A correctly discarded finding is a win.

critlover reports the chain and leaves live exploit development and lab validation to the human.
Everything below follows from these three.

---

## 1 · The flagship-hardening ceiling

The instinct is to point the harness at the most famous, most-audited project in a space — the "elite
flagship." It is almost always the wrong first move. Pure source review of a hardened flagship hits a
ceiling:

- **It's swarmed.** Elite targets draw continuous professional and automated attention. The shallow and
  medium-depth bugs are already found; what's left needs depth you won't reach by reading alone.
- **Dup risk is high.** The more eyes on a target, the more likely your "finding" already sits in a draft
  advisory, an open PR, or a maintainer's inbox. You can burn a whole run and produce only dups.
- **Regressions get patched in days.** Heavy recent maintainer activity means a fresh bug you *do* find
  may be fixed before you file — and newly introduced regressions are the one thing worth watching on
  such targets (see §3c).
- **The easy severity is gone.** What remains tends to be capped by a carve-out (§2) or needs a working
  exploit to prove (§4) — neither is where source review is cheapest.

**Doctrine:** relax the "elite-audited flagship" constraint at stage 0. Prefer a target that is *in-scope
and under-swept* over one that is *famous*. Fame correlates with dup risk, not with yield.

---

## 2 · Trust-boundary carve-outs — attack *around*, never *into*

Mature vendors fence their trust boundaries in public: `SECURITY.md`, a threat-model doc, a program scope
page. Carve-outs declare which bugs the vendor will *not* treat as vulnerabilities. Reading them is not
optional — it is stage 0 — because a chain that lands inside a carve-out is worth **zero**, no matter how
clever, and filing it burns your credibility.

The move is never to argue with a carve-out. It is to **find the path that routes around it**: same sink,
different reachability; same subsystem, a boundary the vendor *does* defend.

| Carve-out (generic shape) | What it excludes | Attack *around* it |
|---|---|---|
| "Inter-node channel is insecure by default; run it on a trusted network." | Anything that assumes you're already on that channel. | A path reachable *without* being on the channel; a default that contradicts the doc; the config surface that's supposed to isolate it. |
| "Device model X is a convenience/legacy emulation, **not** a security boundary." | Guest→host escapes via X. | The subsystems the vendor *does* declare as boundaries (Y, Z); X only as a stepping-stone into one of those. |
| "Malicious migration streams are out of scope (the migration source is trusted)." | Bugs that only fire from a crafted migration stream. | The same corruption reached from an *untrusted* source (guest I/O, network) that doesn't depend on the trusted migration path. |
| "Guest-triggered host memory-allocation DoS is excluded." | Resource exhaustion / OOM from the guest. | Out-of-bounds *write/read* or type confusion in the same path — a different bug class the DoS exclusion doesn't cover. |
| "Only annotated types are CVE-eligible." | Everything not carrying the untrusted-safe annotation. | A reachable path that drives untrusted input *into* an annotated type; or a type reached from untrusted input that *should* be annotated and isn't. |
| "Guest-root-only triggers are self-inflicted." | Anything needing root inside the guest. | The same sink reached **guest-unprivileged** or **network-reachable** — that delta is what makes it a real crit. |

> **Illustrative only.** If `vmm/devices/legacy_uart.c:220` is reachable only from a device the vendor has
> declared a non-boundary, the chain is capped. But if the *same* parsing bug also sits in
> `vmm/devices/netdev.c:514` — a declared boundary reachable from an unprivileged guest — *that* is the
> finding. Same root cause, different trust boundary, opposite verdict.

Carve-outs feed two stages: they go in the venue brief (the run card of `templates/PROGRESS.md`, stage
0) and become each finder's **threat-model filter** (stage 3), so a finder never spends its budget
inside an accepted-risk zone.

---

## 3 · Where crits actually hide

If the flagship-and-into-the-carve-out path is where crits *aren't*, here is the positive program. All
four veins are churn-discoverable at stage 1 and map cleanly onto buckets at stage 2.

**a) The newest, least-swept surface.** Code merged in the last few months has had the fewest eyes — new
routers, new connectors/integrations, a just-added confidential-computing path, a freshly refactored
parser. The auditors haven't caught up yet. This is exactly what `scripts/churn.sh --days 90` surfaces:
rank by recent change, hunt the top of the list first.

**b) Unauth / pre-auth endpoints.** Reachability is half of severity. An endpoint that runs *before*
authentication — a health check that parses a body, a webhook receiver, a login path that touches a
deserializer, an open metrics port — turns a mid bug into a crit because "who can trigger it" drops to
*anyone on the network*. Enumerate the pre-auth surface explicitly and weight it heavily.

**c) Incomplete-fix siblings (variant analysis).** The single highest-EV source-review move. A fresh patch
usually addresses *one* call path or *one* symptom, not the root cause's siblings. Read the patch,
understand the actual root cause, then grep for the same shape elsewhere:
- the same unchecked-length pattern in an adjacent function the patch didn't touch,
- a second caller of the same sink that still passes attacker data,
- the fix applied to the sync path but not the async one.

*Illustrative:* a patch hardens `parse_header()` at `proto/frame.c:88`, but the identical bounds mistake
lives in `parse_trailer()` at `proto/frame.c:140`, untouched. Incomplete fixes are under-swept *by
construction* — everyone assumes the CVE closed the issue.

**d) Network-reachable deserialization.** A recurring high-severity vein, especially in ML-serving and
distributed frameworks. The dangerous shape is a native-object deserializer fed from a channel an attacker
can reach — generically:

```
obj = pickle.loads(sock.recv())        # or recv_pyobj(), torch.load(untrusted_path), yaml.load(...)
```

`pickle` / `recv_pyobj` / `torch.load` / unsafe YAML over a socket, a queue, a model-registry pull, or an
RPC endpoint is arbitrary-code-execution waiting for a reachability proof. The bucket question is only:
*can an unauthenticated or low-privileged party put bytes on that channel?* If yes, it's a crit. If it's
gated behind a trusted-cluster carve-out, it's capped (§2) — grade it honestly either way.

**Bucket hook (stage 2):** pick the taxonomy that fits the target and bias every bucket toward the four
veins above —
- *Web / app backend* — authz/RBAC gates, server-side code-exec sinks, unsafe deserialization, SSTI,
  unauth endpoints, SSRF.
- *Native / VMM (e.g. device emulators)* — per-device / per-subsystem; bounds / state-machine /
  use-after-free; tagged with a reachability tier (guest-unprivileged vs guest-root; network-reachable).
- *Kernel / hypervisor* — per-subsystem; guest-reachability; confidential-computing paths.

---

## 4 · Venue / expected-value map

Severity is not what *you* think the bug is worth — it is what the *venue* will reward, scored against
*their* rubric. Two numbers govern expected value: the venue's realistic **severity ceiling**, and the
**report → payout gap**. critlover deliberately stops at a *source-verified chain* and leaves
working-exploit development to the human, so a venue that pays only on a working PoC has a wide gap, while
a venue that rewards a well-described, source-verified vuln plus a CVE has a narrow one.

| Venue | Realistic ceiling (source-review report) | Report → payout gap | Notes |
|---|---|---|---|
| **Vendor GHSA / `SECURITY.md`** | A CVE + credit; cash rare. | **Narrow** — a clear, source-verified report *is* the deliverable. | Best fit for critlover's output. Reputation currency, not cash. |
| **huntr** (OSS / ML) | Crit CVE + modest cash (often hundreds–low thousands). | **Narrow–moderate** — wants a clear repro; a verified chain usually suffices. | Strong fit for the deserialization vein (§3d). Ceiling = the rubric's crit tier — read it. |
| **Google OSS VRP** | In-scope Google OSS; reward scales with severity + project tier. | **Moderate** — needs the project in scope and a convincing impact case. | Confirm scope at stage 0; out-of-scope project = EV 0. |
| **ZDI** | Higher cash ceilings on enterprise targets. | **Wide** — generally expects a reproducible / working PoC. | critlover gets you a *candidate*; the human still has to weaponize. Budget for that. |

**This is a stage-0 task, not a memory lookup:**
- Ceilings and scope move constantly. **Read the current rubric and scope page before hunting** and record
  them in the run card of `templates/PROGRESS.md`. Never score from memory.
- The gap is the hidden cost. A "crit" that needs two more weeks of exploit development to collect is a
  different EV than one you can file today. Weigh it *before* fan-out, not after.
- Match the vein to the venue: deserialization / authz → huntr & vendor GHSA; VMM / kernel memory
  corruption → ZDI (but mind the gap and the §2 carve-outs).

---

## 5 · The overclaim tax & default skepticism

Finding candidates is easy; admitting which are real is the whole job. In the research this harness was
built from, roughly **four of four** and **five of six** agent "CRIT" claims were overclaimed — inflated
severity, documented behavior mistaken for a bug, an unreachable sink, or a silent dup of something
already filed. That systematic gap is the **overclaim tax**, and **paying it down is where value is
created** — not in the finding step.

So finders are treated as *untrusted*. Every claim clears three gates at stage 4, in order; a failure at
any gate kills or downgrades the claim:

- **Gate A — Source-verify** every link of the chain, reachability included. A sink with no proven path
  from an in-scope actor is not a finding.
- **Gate B — Dup-check** (playbook: `scripts/dup-check-notes.md`) against published advisories, open PRs,
  **and** open issues. A dup is worth zero and costs credibility.
- **Gate C — Recalibrate severity** against the vendor's *own* precedent and rubric — not the finder's
  adjectives — and apply the **carve-out test** here: if a documented carve-out (§2) caps the chain, cap
  it *now* (see §6).

The reward for this skepticism is signal: a short list a human can file without embarrassment. **A finding
you correctly discard is a success** — it protects the venue's signal-to-noise and the hunter's name.

---

## 6 · Stop / pivot rules

Sunk cost is the enemy. These are defaults; tune per target and record the choice in `templates/PROGRESS.md`.

**Dry-round pivot (K rounds).** A *round* is one full fan-out across the current buckets (stage 3) graded
to zero survivors (stage 4).
- **Per bucket:** retire a bucket after **N = 2** finder passes with no survivor. Don't keep re-reading the
  same code hoping.
- **Per target:** after **K = 2** dry rounds, *pivot* — re-run `churn.sh` with a different window to surface
  newer code, switch the bucket taxonomy, or change targets. On a hardened flagship (§1), **K = 1**: if the
  first honest round is dry, the ceiling is likely real — leave.
- **Venue pivot:** if a target is strong but its venue has a report → payout gap (§4) you can't fund, move
  the same findings to a narrower-gap venue, or move on.

**Carve-out cap → downgrade, never inflate.** When a *verified* chain is capped by a documented carve-out:
1. Re-score to what's left after the cap (guest-root-only, migration-source-only, non-boundary device,
   un-annotated type → typically Low / informational / out-of-scope).
2. File at the honest, capped severity **or skip** — whichever the rubric supports. **MED is the default
   filing floor:** a sub-MED result is logged in `templates/PROGRESS.md`, not filed, unless the venue's
   rubric explicitly rewards a Low/Info.
3. **Never** relabel it a crit to clear a quota. Inflating past a published carve-out is the fastest way to
   get a program to stop reading your reports.

> The urge to inflate is strongest right after a long dry spell — which is exactly when the carve-out test
> matters most. Downgrade honestly, log *why* in `PROGRESS.md`, and pivot.

---

## Strategy → pipeline crosswalk

| Doctrine (this memo) | Acts at stage | Artifact |
|---|---|---|
| Relax the flagship constraint; read the rubric & threat model first (§1, §4) | 0 · Target & venue selection | `PROGRESS.md` run card |
| Hunt the newest / least-swept surface (§3a, §3c) | 1 · Scope & scout | `PROGRESS.md` surface map (`churn.sh`) |
| Bias buckets toward the four veins; pick the taxonomy (§3) | 2 · Bucket design | `PROGRESS.md` buckets table |
| Carry the threat-model filter + reachability bar + dup duty (§2, §3, §5) | 3 · Fan-out finders | FINDER-PROMPT (in the skill) + `crit-hunt.js` |
| Three grading gates (A/B/C); carve-out cap; default skepticism (§2, §5, §6) | 4 · Honest grading | `dup-check-notes.md` (Gate B) |
| File only survivors at honest severity; log skips & pivots (§5, §6) | 5 · Write-up & journal | `SUBMISSION.md`, `PROGRESS.md` |

**One line to remember:** hunt the *under-swept* surface, around the *carve-outs*, for *reachable* sinks —
and let honest grading, not the finder's adjectives, decide what gets your name on it.
