> **FICTIONAL — illustrative only.** Invented target and finding to show the shape of a good critlover artifact; not a real vulnerability.

# [`HIGH`] `dataplane/shard-sync` — Deserialization of Untrusted Data — unauthenticated network RCE on a serving worker

*One per survivor — a finding that cleared all three grading gates (source-verify, dup-check,
severity-recalibrate). This is the artifact a human reviews and files.*

> **For responsible disclosure to `huntr`'s official program only.** Authorized, in-scope target.
> This is a **source-review report: a verified chain, not a weaponized exploit.** No working PoC, no
> payload bytes. A human lab-reproduces and files. Do not run anything here against systems you do not
> own or are not invited to test.

---

## At a glance

| Field | Value |
|---|---|
| Target | `acme/modelgate` *(fictional multi-node ML serving gateway)* |
| Commit (HEAD) | `0fae1dface0fface1dcafe0bad0c0ffee5eeded0` — every `file:line` below is true at this sha |
| Component / subsystem | `modelgate/dataplane` (shard-sync listener) → `modelgate/serde/blobcodec` |
| Bug class | `CWE-502 : Deserialization of Untrusted Data` |
| **Severity (vendor rubric)** | **`HIGH`** — vendor "serving-fabric RCE" tier *(recalibrated at Gate C from the finder's claimed CRIT)* |
| Attacker tier | `unauthenticated network client` |
| Venue | `huntr` · rubric `https://huntr.example/acme-modelgate/rubric` *(placeholder)* |
| Status | `ready-for-human-review` |

## Preconditions

*Each precondition is a severity tax — list every one honestly; the reader subtracts.*

- **Config:** **default.** The data-plane listener is enabled out of the box; no non-default flag or feature-gate is required.
- **Deployment:** **network-exposed by default** — each worker binds the data-plane listener on `0.0.0.0:8711` (`dataplane/server.py:31`). No reverse proxy or auth layer sits in front of it in the shipped config.
- **Prior access / privilege:** **none** — unauthenticated.
- **Other bugs needed to chain:** **none — self-contained.**

## Summary

An unauthenticated network client can `POST` a crafted "shard delta" blob to `/v1/shards/sync` on any
ModelGate worker's data-plane listener. The handler passes the raw body straight into a `cloudpickle`
deserializer with no authentication on the data-plane router and no type/trust check on the bytes,
yielding remote code execution in the worker process. The single sentence that fixes its tier under the
**vendor's own rubric**: the executed code is confined to one serving worker inside the multi-node serving
fabric, and the rubric explicitly rates **worker-confined serving-fabric RCE as HIGH** (reserving Critical
for control-plane or cluster-wide compromise) — so despite clearing the generic CRIT bar, it files as **HIGH**.

## Source chain (verified at the pinned commit)

*Every hop is a real `file:line` at `0fae1dface0fface1dcafe0bad0c0ffee5eeded0`, opened and confirmed
during grading (Gate A). Shapes below are illustrative placeholders — fill with the true hops; do not
paste real source verbatim.*

```text
SOURCE   dataplane/shard_sync.py:142   unauth POST /v1/shards/sync — raw request body read as the "shard delta" blob
 → GUARD dataplane/router.py:88        auth middleware is bound to control_router ONLY; data-plane router mounts this route with NO @require_token
 → XFORM dataplane/shard_sync.py:171   raw bytes handed to codec.decode_delta(raw) with no type/trust/length check
 → SINK  serde/blobcodec.py:66         decode_delta → cloudpickle.loads(buf) on attacker-controlled bytes
```

- **Untrusted input:** the full HTTP request body — an opaque binary "shard delta" the attacker fully controls.
- **Failing / absent guard:** there is **no** auth check in the path. Confirmed NOT present on the handler,
  on a decorator, on the data-plane router (`dataplane/router.py:88` binds `require_token` to `control_router`
  only), on any middleware in the app factory, or as a config default. The listener answers before any identity is established.
- **Why it reaches the sink:** `shard_sync` reads the body and calls `decode_delta` unconditionally; `decode_delta`
  is a thin wrapper whose first operation is `cloudpickle.loads`. No branch, size limit, or allow-list intervenes.

## Reachability + attacker tier

- **Trigger actor:** unauthenticated network client *(the lowest tier — no credentials at all)*.
- **Entry channel:** worker data-plane HTTP listener (`0.0.0.0:8711`).
- **Path to the channel:** the route is registered at `dataplane/server.py:54` (`app.mount("/v1/shards", shard_router)`);
  the listener binds all interfaces by default at `dataplane/server.py:31`; no auth decorator guards it.
- **Reachability evidence (`file:line`):** route mount `dataplane/server.py:54` · listener bind `dataplane/server.py:31` · missing-gate line `dataplane/router.py:88`.
- **CRIT-bar check:** a CRIT needs **all** of — unauth-or-low-priv trigger · network-or-equivalent reach ·
  serious impact (RCE / auth-bypass / memory corruption) · default config.
  - unauth trigger — **clears** (no credentials)
  - network reach — **clears** (default `0.0.0.0` listener)
  - serious impact — RCE — **clears** the generic bar, **but fails the vendor's stricter CRIT definition**:
    the vendor reserves Critical for **control-plane or cluster-wide** compromise; this RCE is confined to a
    single data-plane worker inside the serving fabric.
  - default config — **clears**
  - **→ The impact leg fails against the vendor's bar.** Three generic legs clear; because the fourth does not
    meet THIS vendor's Critical definition, it is **not a CRIT** — drop the tier to **HIGH** (see severity justification).

## Trigger / reproduction outline — no working PoC

*The **shape** of a request/command that would exercise the path — so a human can reproduce it in an
authorized lab. **No working exploit, no payload bytes, no shellcode, no gadget chain.** Building and
running a real PoC is the validation lane (below), not this report.*

```text
# OUTLINE — illustrative, non-functional
POST /v1/shards/sync      to a worker's data-plane listener (default :8711)
<auth state>              none — no credentials, no token
<body / arg shape>        a single "shard delta" blob whose serialized object body targets the
                          cloudpickle.loads sink — PAYLOAD INTENTIONALLY OMITTED
Observable success signal out-of-band callback from the worker process, or worker-process behavior
                          change / crash on a benign marker object — NOT an included exploit
```

## Dup-check evidence (Gate B)

*Done before filing — a dup is worth zero and costs credibility. Record what was searched, not just the verdict.*

| Source | Query / symbol searched | Result | Link |
|---|---|---|---|
| CVE / NVD | `modelgate shard sync cloudpickle`, `decode_delta` | none | `https://nvd.example/search?q=modelgate+decode_delta` |
| GHSA + vendor advisories | `acme/modelgate` all advisories; `cloudpickle`, `shard_sync` | none covering this path | `https://ghsa.example/acme/modelgate` |
| Merged PRs | `decode_delta`, `shard_sync`, `require_token data-plane` | none | `https://github.example/acme/modelgate/pulls?q=decode_delta+is:merged` |
| **OPEN** PRs | `decode_delta`, `shard router auth` | none | `https://github.example/acme/modelgate/pulls?q=decode_delta+is:open` |
| **OPEN** issues | `shard sync`, `data-plane auth`, `cloudpickle` | one perf issue on `shard_sync`, not security | `https://github.example/acme/modelgate/issues/388` |
| Incomplete-fix check | sibling advisory `GHSA-xxxx-fake-0001` (`configloader.safe_load`, YAML, control plane) | **different sink, different path, different auth state — NOT its remainder; novel** | `https://ghsa.example/GHSA-xxxx-fake-0001` |

**Conclusion:** **NOVEL — no covering hit.** The one adjacent advisory (`GHSA-xxxx-fake-0001`) is a
control-plane YAML loader behind admin auth; this is an unauth data-plane `cloudpickle` sink.

## Severity justification — scored against the VENDOR'S rubric

*Score against the vendor's own precedent, not a prior and not CVSS-on-autopilot.*

- **Venue rubric:** `https://huntr.example/acme-modelgate/rubric` *(placeholder)* · **tier claimed:** **`HIGH`** *(finder claimed CRIT)*
- **Vendor precedent (their OWN past ratings for similar bugs):**
  - `GHSA-xxxx-fake-0002` — unauth `pickle` RCE on a data-plane worker — rated **HIGH**
  - `GHSA-xxxx-fake-0003` — unauth RCE confined to an inference worker via the tensor codec — rated **HIGH**
  - `CVE-2025-FAKE-55102` — unauth RCE on the **control-plane orchestrator** (cluster takeover) — rated **CRITICAL**
  - `GHSA-xxxx-fake-0004` — unauth metadata SSRF on a worker — rated **MED**
- **Mapping to the rubric:** the two closest precedents (`-0002`, `-0003`) are unauth, network-reachable,
  worker-confined RCE — exactly this shape — and the vendor rated both **HIGH**. The only CRITICAL precedent
  (`-55102`) is distinguished by landing on the **control plane** / achieving cluster-wide compromise, which
  this finding does not. So THEIR criteria put this at **HIGH**.
- **Carve-out test:** **no carve-out excludes this actor/channel.** The reachable channel here is the
  unauthenticated data-plane **HTTP listener**, not the inter-node replication channel. (Contrast: the same
  `cloudpickle.loads` sink is also reachable via raft `AppendEntries`, but *that* route requires an on-fabric
  peer position and therefore lands squarely in the verbatim carve-out — it was dropped to info, not filed. This
  report's channel does not require that position.)
- **Documented-behavior test:** **not** a documented footgun. This is not "load an untrusted model file" (the
  operator-risk carve-out); it is an unauthenticated request to a listener that is on by default deserializing attacker bytes.
- **Reachability tax applied:** none pulled it below HIGH — the chain is unauth, default-config, self-contained.
  The only downward pressure is the **impact-locus cap** (worker-confined, not control-plane), which is exactly
  what moves it CRIT→HIGH and no further.
- **Tie-break:** between CRIT and HIGH, chose **HIGH** — the vendor's own two nearest precedents and its explicit
  "serving-fabric RCE = HIGH" line both put worker-confined RCE there; CRIT is unsupported by their precedent.

## Lane split

**Reporter lane — source review (DONE in this report).** Verified source chain, reachability argument,
dup-check trail, and vendor-precedent severity above. No exploit built, no system touched.

**Validation lane — human (TO DO before / at filing).** Lab-reproduce in an **authorized** environment
(a disposable single-worker ModelGate on an isolated network), develop and run any working PoC there,
confirm the worker-confined-RCE impact and that the HIGH tier holds, then file through `huntr`'s official
channel. Do not validate against non-consenting or production systems.

---

*Prepared by critlover source review. File only if it survived all three gates (A source-verify ·
B dup-check · C severity-recalibrate). **MED is the default filing floor** — a finding recalibrated
below MED is normally logged in PROGRESS.md, not filed; file a LOW/INFO only where the venue's rubric
explicitly rewards it. Never file a dup, documented behavior, or an inflated severity — the short list
you can stake your name on is the product.*
