> **FICTIONAL — illustrative only.** Invented target and finding to show the shape of a good critlover artifact; not a real vulnerability.

# critlover — PROGRESS: `acme/modelgate`

*Per-target hunting journal. One per target. The running record that makes a hunt auditable and
resumable — it carries the live ledger and the per-lead reasoning. Stages 0–3 (venue brief, surface
map, buckets, finder briefs) are recorded in their own sections of this file; the only other template
is `SUBMISSION.md`, one per survivor.*

> **Authorized, in-scope target only.** Responsible disclosure via `huntr`'s official program only.
> This is **source review** — a human validates in a lab and files. **Honest grading over volume:**
> a correctly discarded finding is a win. Never file a dup, documented behavior, or an inflated severity.

---

## Run card (stage 0–1 header)

| Field | Value |
|---|---|
| Target | `acme/modelgate` — multi-node ML inference/serving gateway (fictional) |
| HEAD | `0fae1dface0fface1dcafe0bad0c0ffee5eeded0` — **pinned**; every `file:line` in this file is true at this sha |
| Venue | `huntr` |
| Severity rubric | `https://huntr.example/acme-modelgate/rubric` *(placeholder — read it; never score from memory)* |
| Scope / `SECURITY.md` | `https://github.example/acme/modelgate/blob/main/SECURITY.md` *(placeholder)* |
| Operator | `@omnihyperpunk` · Started `2026-10-05` · Status `closed` |
| Carve-outs | recorded verbatim in the threat-model-filter block below |

**Threat-model filter (summary).** *Carry this into every finder (stage 3) and every grade (stage 4).*
- **In scope:** unauthenticated or low-privilege **network** clients reaching the control-plane API or a
  worker's data-plane listener in a **default** deployment; anything that yields RCE, auth-bypass, or
  cross-tenant model/weight disclosure.
- **Carve-outs — never report into these (recorded verbatim):**
  - `"The inter-node replication channel (raft/gossip between worker nodes) is insecure by default and is assumed to run on a trusted, private network segment. Vulnerabilities that require an on-fabric peer position on this channel are out of scope."`
  - `"ModelGate executes the model code you load. Loading a checkpoint, adapter, or config file from an untrusted source is equivalent to running untrusted code and is the operator's responsibility; 'load untrusted model file → code execution' is not a vulnerability."`
- **Severity rubric, 1-line:** CRIT = unauth RCE on the **control plane** (orchestrator/admin API) or
  cluster-wide takeover / cross-tenant weight exfil; **worker-confined RCE inside the serving fabric = HIGH**;
  authed-admin RCE = HIGH/MED; info-leak within a tenant = MED.

**Clone / scope notes.**
- Clone: blobless + sparse — pulled `dataplane/`, `control/`, `cluster/`, `serde/`, `serve/`. Churn window: `churn.sh --days 90`.
- Freshest / least-swept surface (hunt first): `modelgate/dataplane/` — the shard-sync listener landed ~6 weeks ago in the 0.9 "horizontal sharding" feature; barely reviewed. **(vein: newest/least-swept surface)**
- Incomplete-fix watch: `GHSA-xxxx-fake-0001` just patched `control/configloader.py` `yaml.load`; sibling path to check = every other `cloudpickle` / `torch.load` / `yaml.load` sink reachable **without** auth. **(vein: incomplete-fix siblings → led straight to B1)**
- Pre-auth / unauth entry surface: data-plane listener binds `0.0.0.0:8711` by default with **no** auth middleware; health/metrics/shard routes mounted there. **(veins: unauth/pre-auth endpoints + network-reachable deserialization)**

**Buckets (stage 2).** *One finder owns each; taxonomy = `web/app`.*

| # | Bucket | Churn rank | Seeded crit hypothesis (one, specific) | Reachability tier |
|---|---|---|---|---|
| B1 | data-plane shard-sync listener (`dataplane/`) | hot | unauth `POST /v1/shards/sync` reaches a `cloudpickle.loads` delta decoder with no auth on the data-plane router | unauth-net |
| B2 | control-plane model-management API (`control/`) | med | admin model-register/upload reaches an unsafe loader (`yaml.load` / `torch.load`) | low-priv (admin) |
| B3 | inter-node raft replication (`cluster/`) | med | peer AppendEntries decodes a state blob through the same `cloudpickle` codec | on-fabric peer |
| B4 | model artifact loaders (`serve/`) | cold | checkpoint/adapter load path hits `torch.load` on operator-supplied files | operator-local |

---

## Round ledger (stages 3 → 4)

*One table per fan-out round. **finder verdict** = what the finder self-claimed. **my re-grade** = the
gate outcome after I source-verified + dup-checked (grade as the finder's adversary, not its advocate).
**severity** = final, vendor-calibrated. **status** = disposition.*

Legend — re-grade: `A✓/A✗` source-verify · `B✓/B✗` dup-check · `C:` recalibrate (`from→to`, reason).
Status: `SUBMISSION-<n>` · `LEAD` (unverified hop, logged not filed) · `DROP:dup` · `DROP:carve-out` ·
`DROP:documented` · `DROP:unreachable` · `DROP:unverified` · `DOWNGRADED`.

### Round 1 — fan-out `2026-10-06` · buckets `B1,B2,B3,B4`

| bucket | finder verdict | my re-grade after verify + dup-check | severity | status |
|---|---|---|---|---|
| `B1` | `CRIT: unauth RCE via cloudpickle on /v1/shards/sync` | `A✓ B✓ C: CRIT→HIGH — reachable unauth, but impact is worker-confined; vendor rubric caps serving-fabric RCE at HIGH` | `HIGH` | `SUBMISSION-1` |
| `B2` | `CRIT: unauth RCE via yaml.load on model-register` | `B✗ dup — GHSA-xxxx-fake-0001 covers this exact yaml.load path` | `n/a` | `DROP:dup` |
| `B2` | `HIGH: RCE via torch.load on model-upload` | `A✗ sink unreachable unauth — parent control_router carries @require_admin_token (router.py:40)` | `n/a` | `DROP:unreachable` |
| `B3` | `CRIT: RCE via cloudpickle on raft AppendEntries` | `A✓ C: CRIT→info — requires on-fabric raft peer; lands in the inter-node carve-out` | `info` | `DROP:carve-out` |
| `B4` | `HIGH: RCE via torch.load on checkpoint load` | `A✓ C: capped — operator loads the file; documented footgun` | `info` | `DROP:documented` |

**Round 1 note:** One in-scope survivor, all from the **newest** surface (B1, data-plane). The mature
surfaces paid the overclaim tax in full: B2 was a re-discovery of an already-advised bug **and** an
auth-gated sink mis-tiered as unauth; B3 and B4 were real code paths that die honestly against the two
verbatim carve-outs. Note B1 and B3 share the **same sink** (`serde/blobcodec.py:66` `cloudpickle.loads`) —
the only thing separating a filed HIGH from an out-of-scope info is the **channel**: unauth HTTP listener
(in scope) vs. inter-node raft peer (carved out). Nothing to re-seed; surface is exhausted or structurally
out-of-scope.

### Round 2 — not run

| bucket | finder verdict | my re-grade after verify + dup-check | severity | status |
|---|---|---|---|---|
| — | — | pivoted after one honest round — survivor in hand, remaining surface dup/carve-out/documented | — | — |

---

## Overclaim tax tally

*The overclaim tax is the point of the harness — surface it, don't bury it. Per bucket: claimed
CRIT/HIGH vs what actually survived honest grading.*

| Bucket | Finder CRIT claims | Finder HIGH claims | Survived (any sev) | Filed |
|---|---|---|---|---|
| `B1` | `1` | `0` | `1` | `1` |
| `B2` | `1` | `1` | `0` | `0` |
| `B3` | `1` | `0` | `0` | `0` |
| `B4` | `0` | `1` | `0` | `0` |
| **Total** | `3` | `2` | `1` | `1` |

**Target overclaim ratio:** **1/3 CRIT claims survived — and the survivor dropped a full tier to HIGH.**
0/2 HIGH claims survived. The finders are pattern-matching the inflation seen in the source research
(~4/4 and 5/6 CRIT overclaim): here 2 of 3 CRIT claims collapsed outright and the sole survivor was
over-tiered. Graded as adversary, not advocate — every "CRIT" was made to earn its channel, its reach,
and its impact locus independently.

---

## Per-lead detail

*One block per notable claim (survivor or closed). The reasoning that the ledger row abbreviates.
Cite real `file:line` hops at the pinned sha; keep examples generic — no real source pasted, no PoC.*

### Lead `B1-L1` — unauth data-plane shard-sync → `cloudpickle.loads` — finder claimed `CRIT`

- **Chain (verified hops):**
  - source `modelgate/dataplane/shard_sync.py:142` — handler for `POST /v1/shards/sync` reads the raw request body (a "shard delta" blob)
  - guard `modelgate/dataplane/router.py:88` — auth middleware is bound to `control_router` **only**; the data-plane router mounts `shard_sync` with **no** `@require_token` (confirmed absent on handler, decorator, router, and app default)
  - transform `modelgate/dataplane/shard_sync.py:171` — raw bytes handed to `codec.decode_delta(raw)` with no type/trust check
  - **sink** `modelgate/serde/blobcodec.py:66` — `decode_delta` calls `cloudpickle.loads(buf)` on attacker-controlled bytes
- **Reachability:** actor = unauth network client · channel = data-plane HTTP listener `0.0.0.0:8711` (default-on, `dataplane/server.py:31`; route mounted `dataplane/server.py:54`) · preconditions = **default config, none, self-contained**.
- **Verdict:** **KEPT → SUBMISSION-1 at HIGH.** Gates A✓ (every hop opened and confirmed) and B✓ (novel).
  Gate C recalibrated CRIT→HIGH: all four generic CRIT legs clear, but the vendor's CRIT definition
  additionally requires **control-plane / cluster-wide** impact; this RCE is confined to one serving
  worker, which the rubric explicitly rates HIGH.
- **Dup evidence:** searched CVE/NVD, GHSA + vendor advisories, merged + **OPEN** PRs, **OPEN** issues for
  `decode_delta` / `shard_sync` / `cloudpickle.loads`; result **novel**. Incomplete-fix check vs
  `GHSA-xxxx-fake-0001`: that advisory patched `configloader.safe_load` (YAML, control plane) — different
  sink, different path, different auth state; this is **not** its remainder.

### Lead `B3-L1` — raft AppendEntries → same `cloudpickle.loads` — finder claimed `CRIT`

- **Chain (verified hops):**
  - source `modelgate/cluster/raft_sync.py:98` — peer `AppendEntries` handler decodes a peer state blob
  - guard — peer identity is **network-trust only**; the channel has no cryptographic peer auth *by design*
  - **sink** `modelgate/serde/blobcodec.py:66` — same `cloudpickle.loads` as B1-L1
- **Reachability:** actor = a node already holding an **on-fabric raft peer position** · channel = inter-node replication · precondition = attacker must already be a peer on the private cluster network.
- **Verdict:** **CLOSED — DROP:carve-out.** Gate A✓ (the path is real and the sink is identical to the
  survivor's), but Gate C caps it: the chain requires exactly the position the verbatim carve-out excludes —
  *"...require an on-fabric peer position on this channel are out of scope."* Capped CRIT→info; logged, not filed.
- **Dup evidence:** n/a for filing — closed on carve-out before dup mattered; recorded so a future operator
  doesn't re-walk it.

### Lead `B2-L1` — control-plane model-register → `yaml.load` — finder claimed `CRIT`

- **Chain (verified hops):**
  - source `modelgate/control/configloader.py:40` — `POST /v1/admin/models/register` body parsed as YAML
  - **sink** `modelgate/control/configloader.py:58` — `yaml.load(body, Loader=yaml.Loader)` (unsafe full loader)
- **Reachability:** actor = authenticated admin · channel = control-plane API · precondition = admin token.
- **Verdict:** **CLOSED — DROP:dup.** Gate B✗: `GHSA-xxxx-fake-0001` covers this exact `yaml.load` at this
  exact path, with a fix already in an **OPEN** PR. Worth zero and costs credibility to file. (Secondary
  issue: it is also admin-gated, so the finder's "unauth CRIT" framing was wrong on reach as well as on novelty.)
- **Dup evidence:** GHSA hit `GHSA-xxxx-fake-0001` (`https://ghsa.example/GHSA-xxxx-fake-0001`); confirmed
  same symbol + same `configloader.py` path; OPEN remediation PR `#412` (`https://github.example/acme/modelgate/pull/412`).

---

## Stop / pivot log

*Defaults (tune per target; record every decision here). Per bucket: retire after **N = 2** dry finder
passes. Per target: **pivot after K = 2** dry rounds (**K = 1** on a hardened flagship — if the first
honest round is dry, the ceiling is real; leave).*

| When | Decision | Why |
|---|---|---|
| `R1 / 2026-10-06` | retire B3 and B4 | both die structurally against the two verbatim carve-outs (inter-node channel; operator-loads-file) — no in-scope surface left to sweep |
| `R1 / 2026-10-06` | park B2 for a focused incomplete-fix re-run | this round's B2 was a dup + a mis-tiered auth-gated sink; revisit only when control-plane churn moves |
| `R1 / 2026-10-06` | **stop at K=1 — do not fan out Round 2** | survivor in hand (B1→SUBMISSION-1); remaining surface is dup / carve-out / documented, not dry-but-promising — a second round would only re-pay the tax |

---

## Final honest verdict

- **Rounds run:** `1` · **Buckets:** `4 explored / 2 retired (B3 carve-out, B4 documented)` · **Survivors filed:** `1` (`SUBMISSION-1`)
- **Overclaim summary:** 3 CRIT + 2 HIGH claimed → **1 survived**, recalibrated down a tier to HIGH. Tax paid this run: 4 of 5 claims inflated (2 CRIT collapsed, 2 HIGH collapsed, 1 CRIT over-tiered).
- **Why stopped / pivoted:** survivor in hand; the rest of the surface is structurally out-of-scope by the
  vendor's own carve-outs or already covered by a prior advisory — not a surface that another honest round improves.
- **Residual leads for a future run:** (1) watch for **new** data-plane routes mounted on `dataplane/server.py`
  without the auth middleware — the B1 class recurs whenever a route is added there; (2) re-run B2 as an
  incomplete-fix sweep once `GHSA-xxxx-fake-0001`'s remediation lands, to check the fix's siblings.
- **One-line call:** "1 HIGH filed to huntr (unauth serving-fabric RCE, recalibrated from a claimed CRIT);
  B3/B4 retired as out-of-scope by the vendor's own carve-outs; target closed at K=1."
