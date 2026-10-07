# critlover — PLAYBOOK: ML-serving / LLM-inference frameworks

*A per-target-class playbook. It specializes the pipeline's **stages 0–5** for one surface:
ML-serving / LLM-inference frameworks — Python / FastAPI / async-RPC inference servers, model
gateways, agent/tool platforms, and RAG backends. It does not replace the runbook
([`.claude/skills/crit-hunt/SKILL.md`](../.claude/skills/crit-hunt/SKILL.md)) or the doctrine
([`strategy/STRATEGY.md`](../strategy/STRATEGY.md), §-refs below) — it tells you which buckets, sinks,
and carve-outs to expect here, and where the crits actually sit.*

> **Authorized, in-scope targets only. Responsible disclosure via the vendor's official program only**
> (huntr / vendor GHSA / Google OSS VRP / ZDI). **Honor the carve-outs — attack *around* them, never
> report *into* accepted behavior.** This is **source review**: a verified chain, not a weaponized
> exploit. No working PoC, no payload bytes. A human validates and files. **Every example below is
> illustrative** — fictional `file:line`, no real target source, no exploit code.

---

## 1 · Why this class yields crits

This class inverts the **flagship-hardening ceiling** (STRATEGY §1): instead of a swarmed, hardened
target you get a large, fast-moving, under-swept surface where **all four veins converge** (README /
CLAUDE canon). Reachable sinks are common and the dup field is thinner than on a flagship — so it is a
high-yield stage-0 pick. Grade it just as hard anyway: the overclaim tax (STRATEGY §5) is real here too.

- **Large, fast-moving, new surface.** The inference / agent / RAG ecosystem is young and ships weekly.
  New routers, new tool/function loaders, and new connectors land faster than auditors read them — that
  is STRATEGY §3a (the newest / least-swept surface) *by construction*.
- **Python toolchain fit.** The class is Python + FastAPI + async RPC, and the harness's dangerous-sink
  census ([`scripts/sink-grep.sh`](../scripts/sink-grep.sh)) is tuned for exactly these sinks
  (`pickle` / `torch.load` / `exec` / Jinja). The §3d deserialization vein was written with this class
  in mind.
- **Network-reachable by default.** These are *servers*: they bind HTTP / gRPC / ZMQ ports, pull from
  model registries, and open worker channels. Reachability is half of severity (STRATEGY §3b) — and
  here it is frequently *free*.
- **Many fresh routers / connectors.** Each new endpoint, fetcher, and loader is a candidate entry
  channel and an unauth / pre-auth lead — under-swept because nobody has caught up to it yet (§3a, §3c).

---

## 2 · Bucket taxonomy for this class

The reference taxonomy to instantiate as rows in the buckets table of
[`templates/PROGRESS.md`](../templates/PROGRESS.md) (stage 2). Seed **one specific crit hypothesis per
bucket**, *around* the carve-outs (§5), never into them. Churn-rank them first (§7, stage 1) and give
the hottest surface its own finder.

| # | Bucket | Seeded crit hypothesis (one, specific) | Reachability tier | Vein |
|---|---|---|---|---|
| B1 | **authz / RBAC + API-key paths** | a handler on a *new* router is missing the API-key / RBAC dependency its siblings carry → wrong-tenant or unauth access | unauth-net / low-priv | §3b |
| B2 | **SCIM / user-provisioning** | a SCIM `/Users` or `/Groups` endpoint provisions or escalates a role without verifying the caller's admin scope | unauth-net / low-priv | §3b |
| B3 | **server-side code-exec via tool / function / pipe loaders** | a tool / function / "pipe" spec from a request body reaches `exec`/`eval` or an `importlib` loader | low-priv / unauth-net | code-exec |
| B4 | **unsafe deserialization over network channels** | a worker / RPC / ZMQ channel decodes a native object from bytes a low-priv party can place | unauth-net / on-cluster | **§3d** |
| B5 | **SSTI in prompt templating** | a caller-supplied prompt / template *string* reaches Jinja `from_string` / `render` with no sandbox | low-priv / unauth-net | SSTI |
| B6 | **unauth / pre-auth endpoints** | a health / metrics / webhook / model-load endpoint parses a body *before* the auth middleware runs | unauth-net | §3b |
| B7 | **SSRF via fetchers / connectors** | a RAG / connector fetcher takes a caller-controlled URL and issues a server-side request to internal metadata / services | low-priv / unauth-net | §3b + SSRF |
| B8 | **model-file / weight / adapter loaders** | a model / adapter / checkpoint keyed by a *caller-nameable* registry path is loaded via `torch.load` / `pickle` | low-priv / on-cluster | **§3d** |

> B8 commonly collides with the *"untrusted model files are the operator's risk"* carve-out (§5, #4):
> seed it as the path that makes the artifact arrive **without the operator choosing it** — route around
> the carve-out, don't report into it.

---

## 3 · Signature sinks to grep

Run [`scripts/sink-grep.sh`](../scripts/sink-grep.sh) over the sparse checkout and treat every hit as a
**lead, never a finding** (the script's own header). A sink is only half a chain; the finder's whole job
is Gate A — **connect it back to an untrusted source with an unbroken, guard-free path**. The right-hand
column is that connect-back question.

| Sink symbol(s) | `sink-grep.sh` class | Connect it back to an untrusted source — the question to answer |
|---|---|---|
| `pickle.loads` · `cPickle` · `_pickle` · `cloudpickle` · `marshal.loads` | `deser` | What network / IPC / queue bytes reach this `loads()`, and who can place them under default config? |
| `recv_pyobj(` | `deser` | Which socket is this — who **binds** it, on what interface (`0.0.0.0`?), and is anything authenticating the peer before the decode? (This is the §4 vein.) |
| `torch.load(` | `deser` | Is the path / registry key **caller-nameable**? `torch.load` unpickles unless `weights_only=True` — check the flag; an untrusted artifact + default flag = RCE. |
| `yaml.load(` | `deser` | Is `Loader=` a `SafeLoader` / is it `yaml.safe_load`? Those are safe — *confirm the loader*. Full `Loader` + request-sourced YAML = code-exec. |
| `exec` · `eval` · `compile` · `shell=True` | `exec` | Does a request field (tool spec, template, expression, config value) reach it? Filter the benign noise (`re.compile`, `str.format`). |
| `.from_string(` · `render_template_string(` · `Template(` · `.render(` | `ssti` | Is the **template text** attacker-controlled (not just the data passed to a fixed template)? `from_string(user_input)` is the classic; `.render(data)` on a fixed template is fine. |
| `httpx` · `requests` · `aiohttp` · `urllib` fetchers | *(manual — not a `sink-grep.sh` class; grep these directly)* | Is the URL / host caller-controlled, and can it reach internal addresses (`169.254.169.254`, `localhost`, cluster DNS) with no allowlist? That is the SSRF chain (B7). |
| `torch.load` / `pickle` on a model / adapter / checkpoint artifact | `deser` | Does the artifact arrive from a caller-nameable hub / registry / network path rather than an operator-chosen local file? If so it routes around the operator-risk carve-out (§5, #4). |

Honest-grading reminder (sink-grep.sh footer / STRATEGY §5): a sink with no proven path from an in-scope
actor is **not** a finding. For each hit → (1) prove reachability, (2) dup-check, (3) re-score vs the
vendor rubric. Capped by a documented carve-out? downgrade, never inflate.

---

## 4 · The recurring high-severity vein

The flagship vein for this class (STRATEGY §3d): **a native-object deserializer fed from a
network-reachable channel = unauth RCE whenever a low-priv party can put bytes on that channel.** The
channel is usually a worker / data-parallel socket (**ZMQ**), an **IPC** path, a secondary **RPC / gRPC**
listener, a **model-registry** pull, or a **task queue**. The sink is `recv_pyobj` / `pickle.loads` /
`torch.load` / full-`Loader` YAML on whatever the channel delivers.

**The generic reachability question — the only question this bucket turns on:**

> **Can an unauthenticated or low-privileged party put bytes on that channel under default config?**

Decompose it when you grade (Gate A) — the finder must answer all four:

1. **What binds the channel, and to what interface?** A `0.0.0.0` default bind on a channel the docs
   call "internal" is the whole finding (see §5, #2).
2. **What authenticates the bytes before the deserializer runs?** None / a shared secret / mTLS — and is
   that on by default?
3. **Under default config, who can send?** Unauth network client · any cluster tenant · only a trusted
   peer. The lower the privilege, the higher the severity.
4. **If a carve-out claims "trusted network", is there a default or a sibling path that contradicts it?**
   (§5) A single-node / default deploy where the "cluster" channel is still live counts.

If an **unauth-or-low-priv** party clears 1–4, it is the §3d crit (and the full CRIT bar: unauth/low-priv
+ network reach + serious impact + default config). If only a **trusted peer** clears it, the carve-out
caps it — downgrade at **Gate C** (STRATEGY §6), never inflate.

```text
# ILLUSTRATIVE ONLY — fictional file:line, no payload, no PoC
SOURCE  serving/rpc/worker_zmq.py:71   PULL socket bound 0.0.0.0:5555, no peer auth
 → GUARD serving/rpc/worker_zmq.py:—   (expected shared-secret / HMAC check is ABSENT)
 → XFORM serving/rpc/dispatch.py:40    received frame handed to the task runner, no type check
 → SINK  serving/rpc/worker_zmq.py:71  recv_pyobj() → native unpickle of attacker bytes
reach:   any host that can reach :5555 — default bind is 0.0.0.0, no auth  => clears the bar
```

---

## 5 · Trust-boundary carve-outs — and the attack-*around* move

Mature ML-serving vendors fence these boundaries in `SECURITY.md` / threat-model docs. Record them
**verbatim** in the PROGRESS run card at stage 0; a chain that lands inside one is worth **zero**
(STRATEGY §2). The move is never to argue — it is to find the path with the **same sink, different
reachability** that routes into a boundary the vendor *does* defend (usually the public API, default
config, single-node deploy). Shapes are generic — not any specific product.

| Carve-out (generic shape, as vendors publish it) | What it excludes | Attack *around* it |
|---|---|---|
| **"The inter-node / data-parallel channel is insecure by default — run it on a trusted network."** | Anything that assumes you are *already* on that channel (the multi-node RCE). | Reach the **same deserializer without being on the trusted channel**: a default `0.0.0.0` bind, a single-node / default deploy where the "cluster" channel is still live, or a front-door router that **forwards attacker bytes onto it**. Land it in the public-API boundary the vendor defends. |
| **"A secondary RPC / gRPC listener is internal-only."** | World / guest access to that listener. | Check the **actual default bind address and auth** — "internal-only" in docs often binds `0.0.0.0` with no credential. Or find a public endpoint that **proxies to** the internal listener. The defended boundary is "internal-only *as actually configured by default*". |
| **"An `INSECURE_SERIALIZATION`-style env flag gates the unsafe path (off by default)."** | The unsafe path *when the flag is off*. | Audit the **un-gated sibling sinks**: a second deserializer the flag never wraps, a loader that unpickles regardless, or the flag read in one module but not the parallel one (incomplete gating = §3c sibling). The flag defends **one** path — find the one it forgot. |
| **"Loading untrusted model files is the operator's risk."** | A user who *deliberately* loads a malicious local model. | Make the artifact arrive **without the operator choosing it**: a hub / registry pull keyed by a caller-controlled name, an auto-download of a request-named model, a network-fetched adapter / LoRA / checkpoint, or a cache-poisoning path. If an unauth / low-priv request causes the load, the operator never "chose" it — that is the API boundary, not the carve-out. |

> When the **only** path you can prove sits inside a carve-out, it is capped: re-score to what's left at
> Gate C and either file at that honest (capped) severity or skip — **MED is the default filing floor**
> (CLAUDE canon). Never relabel a carved-out chain CRIT to clear a quota (STRATEGY §6).

---

## 6 · Venue fit

Severity is what the *venue* rewards against *its* rubric, not what the finder's adjectives claim
(STRATEGY §4 / SKILL Gate C). For this class:

- **huntr** — **strong fit**, especially the §3d deserialization vein (B4, B8) and the loader / SSTI
  buckets (B3, B5). Crit CVE + modest cash; report→payout gap is narrow–moderate (wants a clear repro, a
  verified chain usually suffices). Ceiling = the rubric's crit tier — **read it**.
- **Vendor GHSA / `SECURITY.md`** — **strong fit**; a clear, source-verified report *is* the deliverable
  (narrow gap). CVE + credit, cash rare. Best home for critlover's output.
- **Google OSS VRP** — only if the project is in Google's OSS scope; confirm at stage 0 or EV is 0.
- **ZDI** — wider gap (generally expects a working PoC); the harness hands you a *candidate*, the human
  still weaponizes.

**The ceiling caveat for this class: the realistic ceiling is often HIGH, not CRIT** — because vendors
**cap the headline multi-node / trusted-network RCE** with the §5 carve-outs. So:

- Read the `SECURITY.md` and pull 3–5 of the vendor's **own** past ratings for similar bugs; score at
  **Gate C against that precedent**, not CVSS-on-autopilot.
- The EV move is the **unauth / default-config path the carve-out does *not* cover** (§5) — that is what
  clears the full CRIT bar. A chain that only works on the carved-out trusted channel is a HIGH-or-lower,
  honestly.
- Capped below MED by a carve-out → **logged in PROGRESS.md, not filed**, unless the rubric explicitly
  rewards a Low/Info.

---

## 7 · Stage-by-stage checklist (stages 0–5)

The pipeline, specialized for this class and mapped to the recon scripts + the FINDER-PROMPT. Keep the
journal in [`templates/PROGRESS.md`](../templates/PROGRESS.md) throughout.

| Stage | This-class moves | Tool / artifact |
|---|---|---|
| **0 · Target & venue** | Pick an in-scope huntr / GHSA framework over the swarmed flagship (§1). Read `SECURITY.md`; record the §5 carve-outs **verbatim**. | PROGRESS.md run card + threat-model-filter block |
| **1 · Scope & scout** | Sparse-clone the `server` / `router` / `loader` / `connector` / `rpc` dirs; pin the sha. Rank the freshest routers & connectors. Enumerate listeners / ports / channels and the **pre-auth** surface. | [`clone.sh`](../scripts/clone.sh) · [`churn.sh`](../scripts/churn.sh)` --days 90` · `entrypoints.sh` *(this round)* |
| **2 · Bucket design** | Instantiate the §2 taxonomy as PROGRESS buckets (churn-ranked). Census sinks to seed each hypothesis. Isolate handlers whose auth gate is **blank**. | [`sink-grep.sh`](../scripts/sink-grep.sh)` deser exec ssti` · `ONLY_NONE=1 `[`authz-census.sh`](../scripts/authz-census.sh) |
| **3 · Fan-out finders** | One finder per bucket. Carry the §5 carve-outs as the **threat-model filter** and the §4 reachability question as the **bar**. Finders report chains, flag dups — they do not self-clear. | **FINDER-PROMPT** (SKILL stage 3) · [`crit-hunt.js`](../.claude/workflows/crit-hunt.js) |
| **4 · Honest grading** | Three gates in order — **A** source-verify every hop · **B** dup the sink symbol + subsystem across advisories / PRs / issues · **C** recalibrate vs vendor precedent + carve-out cap. Check the incomplete-fix siblings of any recent CVE. | `dup-scan.sh` *(this round)* + [`dup-check-notes.md`](../scripts/dup-check-notes.md) (Gate B) · `patch-variant.sh` *(this round, §3c siblings)* |
| **5 · Write-up & journal** | One SUBMISSION per survivor: chain, reachability, dup trail, vendor-precedent severity. Update the overclaim tally. Respect the **MED floor**. | [`SUBMISSION.md`](../templates/SUBMISSION.md) · PROGRESS.md |

**Stop / pivot (STRATEGY §6):** retire a bucket after **N = 2** dry finder passes; pivot the target after
**K = 2** dry rounds (re-run `churn.sh` with a newer window to surface fresher routers before leaving).

---

*Part of [critlover](../README.md). Doctrine: [`strategy/STRATEGY.md`](../strategy/STRATEGY.md)
(§1 ceiling · §2 carve-outs · §3 veins · §4 venues · §5 overclaim tax · §6 stop/pivot). Runbook:
[`.claude/skills/crit-hunt/SKILL.md`](../.claude/skills/crit-hunt/SKILL.md). **One line:** hunt the
fresh routers / connectors, around the trusted-network carve-outs, for a deserializer an unauth party can
feed — and let honest grading, not the finder's adjectives, set the severity.*
