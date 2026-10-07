# critlover — PLAYBOOK: KVM / kernel hypervisor + distributed-serving control planes

*Target-class playbook for the **in-kernel hypervisor** — KVM and the kernel-side virtualization
subsystems — and for the **control plane** of distributed LLM-serving clusters. It specializes the
canonical pipeline (stages 0–5; [`.claude/skills/crit-hunt/SKILL.md`](../.claude/skills/crit-hunt/SKILL.md))
for the **guest→host** trust boundary and its serving-cluster cousin, the network-reachable
deserialization channel. It is the in-kernel sibling of [`playbooks/vmm-devices.md`](vmm-devices.md)
(the **userspace** VMM device models in C) and shares the deserialization vein with
[`playbooks/ml-serving.md`](ml-serving.md). Doctrine it builds on:
[`strategy/STRATEGY.md`](../strategy/STRATEGY.md) §1–§6.*

> **Authorized, in-scope targets only; responsible disclosure via the official program only** (Google
> OSS VRP / ZDI / the kernel CNA / vendor GHSA). **Honor the vendor's published threat model and
> trust-boundary carve-outs — attack *around* them, never report *into* accepted behavior.** **Report
> the chain, not an exploit:** no working VM-escape or control-plane PoC, no payloads, no shellcode, no
> gadget chains — a human validates in an authorized lab and files. **Every example below is
> illustrative** — fictional `file:line`, no real target source, no exploit code.

---

## 1 · Threat model — the guest is untrusted; a guest→host escape is HIGH/CRIT by default

Invert the web/app model. There the untrusted actor is a network client reaching an endpoint; here the
untrusted actor is **the guest** reaching the host across the guest→host boundary. The guest kernel —
and, more strictly, an *unprivileged guest-userspace process* — is assumed hostile. Anything it can do
to drive host-side state is in the threat model.

The impact ceiling already sits at the top of the scale, so the default severity is high. Each of:

- **guest-triggered host memory corruption** (OOB read/write, type confusion, double-fetch),
- **use-after-free** in a host-side object whose lifetime the guest can influence, or
- **privilege escalation** out of the VM into the host kernel / hypervisor (VM escape),

maps directly to **HIGH / CRIT** on every venue's rubric, because the yield is host compromise or a
cross-tenant escape. You do **not** have to chain to a working RCE to justify the tier — a proven
guest→host OOB write *is* the finding (critlover stops there; the human weaponizes, §7).

**But reachability is still half the severity.** *Who* reaches the entry channel — a KVM `ioctl`, a
hypercall / VM-exit, an MMIO/PIO trap into the emulator, a virtqueue kick, a `vsock` packet, a
confidential-computing secure-call, or a serving control-plane socket (§3) — decides whether a real bug
is a crit or a capped curiosity. Tier the trigger actor explicitly; every precondition is a tax
(Gate C):

| Attacker tier (this class) | Where they sit | Default weight |
|---|---|---|
| **Guest-unprivileged** | an unprivileged process inside the guest | **highest** — the real untrusted boundary; the canonical guest→host escape tier |
| **Guest-root** (guest CPL0 / guest kernel) | the guest's own kernel | high — but test the carve-out (§4); some vendors treat guest-root as a weaker trigger |
| **Network peer on a control plane** | reaches a coordinator / worker socket (§3) | high for the serving crossover — reach is "on the network" |
| **Host-local user** | already on the host | usually *outside* the hypervisor threat model — attack *around* it (§4) |
| **Trusted migration source / cluster peer** | inside a declared carve-out | capped — route around it or downgrade honestly (§4, §6) |

> The reachability tier is not decoration — it is the difference between a filed crit and a logged lead.
> Carry it into the FINDER-PROMPT's reachability bar (stage 3), prove it at Gate A (§5), and tax it at
> Gate C.

---

## 2 · Bucket taxonomy by subsystem — newest / least-swept first

One finder owns each bucket (stage 2). Order by sweptness: the freshest surface has the fewest prior
eyes and the thinnest dup field (STRATEGY §1, §3a). Upstream KVM is a hardened flagship, so expect the
ceiling (STRATEGY §1) and weight the freshest subsystem and the incomplete-fix siblings (§6) accordingly.
[`scripts/churn.sh`](../scripts/churn.sh)` --days 90` confirms which bucket is actually hottest in *your*
target; `entrypoints.sh` *(this round)* seeds each bucket's entry channel (§5).

| # | Bucket (subsystem) | Sweptness | Untrusted input / entry channel | Recurring crit shape (seed one, specific) | Typical tier |
|---|---|---|---|---|---|
| **K1** | **Confidential computing** — TDX / SEV-SNP / `guest_memfd` | **freshest** | secure-call / GHCB fields, shared↔private page-conversion requests, newly-added ioctls | shared↔private **page-state race / UAF**, missing validation on a secure-call field, double-fetch of a guest-controlled field | guest-unpriv / VMM-driven |
| **K2** | **MMU / EPT paging** — second-level translation, memslots, dirty-logging | hot | guest faults, memslot create/move/delete, page-table walks | **race between memslot update and fault handling**, page refcount / UAF on teardown, large-page merge/split mishandling | guest-unpriv |
| **K3** | **Instruction emulator** — decode + emulate on MMIO / trap | warm | the trapped instruction stream + operands the guest controls | **decode length / operand-size confusion**, a missing segment/limit check, emulating an op that touches host state | guest-unpriv |
| **K4** | **Nested virtualization** — VMCS / VMCB shadowing (VMX / SVM) | warm | L1-supplied control structures on VMLAUNCH/VMRESUME, nested EPT | **state confusion between `vmcs01` / `vmcs02`**, a missing field validation, a nested-EPT walk bug | guest-root (L1) — check §4 |
| **K5** | **vhost / vsock IPC** — *in-kernel* virtio dataplane + socket transport | warm | virtqueue descriptors (index / len), `vsock` packet headers | **descriptor-ring index/length validation**, UAF between guest kick and host worker thread, a socket-layer bug reachable from guest userspace | guest-unpriv |

> **Lane note on K5.** The *userspace* virtio **device model** (QEMU/crosvm, C/Rust) is
> [`playbooks/vmm-devices.md`](vmm-devices.md)'s lane; K5 here is the **in-kernel** `vhost` dataplane and
> the `vsock` transport — same wire format, different trust-boundary implementation.

> **Illustrative only (fictional paths).** A CoCo page-state UAF near `arch/x86/kvm/vmx/tdx.c:412`; a
> memslot/fault race near `arch/x86/kvm/mmu/tdp_mmu.c:980`; an operand-size slip near
> `arch/x86/kvm/emulate/decode.c:1540`; a `vmcs02` field left unvalidated near
> `arch/x86/kvm/vmx/nested.c:277`; a descriptor-length check missing near `drivers/vhost/net.c:355`.
> None are real — open the true lines in *your* target at the pinned sha and verify (Gate A, §5).

Bias every bucket toward the four veins (STRATEGY §3): the **newest** code (CoCo, a just-added paravisor
path); **pre-privilege** reach (the unauth / pre-auth vein, here = **guest-userspace, not guest-root**);
**incomplete-fix siblings** (§6); and **network-reachable deserialization** (§3). Seed the hypothesis
*around* the carve-outs, never into them (§4).

---

## 3 · The deserialization-RCE vein in distributed-serving control planes (crossover with `ml-serving.md`)

A distributed LLM-serving stack splits into a **dataplane** (the model forward pass across
tensor/pipeline-parallel workers) and a **control plane** (a scheduler / coordinator ↔ workers for task
dispatch, weight / KV-cache transfer, collective-RPC, health and metrics). The **control plane is the
attack surface**, and its recurring crit is the one [`playbooks/ml-serving.md`](ml-serving.md) catalogs
in full and STRATEGY §3d names: a native-object deserializer fed from a network-reachable channel.

The crossover is that the bucket question is *identical* to the guest→host question in §1 — only the
boundary changes:

> **Can a low-priv party put bytes on the channel?**

For the control plane that means: is the coordinator / worker socket **bound on `0.0.0.0` with no auth
under default config**? Is it reachable from a co-tenant, a neighbouring pod, or the tenant network —
rather than only from a trusted scheduler? [`scripts/authz-census.sh`](../scripts/authz-census.sh)
(and `ONLY_NONE=1 …` for the unauth subset) and [`scripts/sink-grep.sh`](../scripts/sink-grep.sh)` deser`
seed both ends; the finder connects the socket to the sink.

```text
# ILLUSTRATIVE ONLY — fictional file:line, no payload, no PoC
SOURCE  serving/coord/rpc_listener.py:66   PULL/REP socket bound 0.0.0.0, no peer auth
 → GUARD serving/coord/rpc_listener.py:—   (expected shared-secret / mTLS check is ABSENT)
 → XFORM serving/coord/dispatch.py:28       received frame handed to the task runner, no type check
 → SINK  serving/coord/pyobj.py:41          recv_pyobj() → native unpickle of attacker bytes
reach:   any party who can reach the coordinator socket — default bind 0.0.0.0, no auth  => clears the bar
```

`recv_pyobj()` / `pickle.loads()` over a coordinator socket, or `torch.load()` of a checkpoint pulled
over the network, is arbitrary code execution **waiting for a reachability proof**. The usual cap is a
carve-out — *"run the control plane on a trusted / isolated network"* (§4). Grade it honestly: if the
channel really is only reachable by a trusted peer, the chain is capped (downgrade at Gate C); if the
default bind or a co-tenant path contradicts the doc, *that* is the finding. Full taxonomy, signature
sinks, and the four-part reachability decomposition: **[`playbooks/ml-serving.md`](ml-serving.md)** §3–§4
and STRATEGY §3d.

---

## 4 · Carve-outs & attack-*around* (generic)

Mature hypervisor and serving projects fence their trust boundaries in public (`SECURITY.md`, a
threat-model doc, the program scope page). Record them **verbatim** in the run card of
[`templates/PROGRESS.md`](../templates/PROGRESS.md) at stage 0; a chain that lands inside one is worth
**zero** (STRATEGY §2). Never argue with a carve-out — find the path with the **same sink, different
reachability** that routes onto the side the vendor *does* defend.

| Carve-out (generic shape) | What it excludes | The move that lands on the defended side |
|---|---|---|
| **"Local-only / host-local attacker is not a boundary."** | bugs triggered from the host side | reach the *same* corruption from the **guest** (the real untrusted boundary) or over the network — via `vsock` from guest-userspace, or a network-reachable control socket (§3) — not host-local. |
| **"Guest-root is self-inflicted."** | anything needing CPL0 inside the guest | reach the *same* sink from **guest-userspace** — an `ioctl` / virtio / `vsock` path an unprivileged guest process drives without guest-root. That tier delta is what makes it a crit (STRATEGY §2, the guest-root row). |
| **"Run the inter-node / control-plane channel on a trusted, isolated network" / "the migration source is trusted."** | anything that assumes you are *already* on that channel | a path reachable **without** being on it — a default `0.0.0.0` bind that contradicts the doc, a guest- or network-reachable trigger that does not depend on the trusted stream, or the isolation config **failing open** on a default / single-node deploy. |

> **If you cannot route around it, downgrade — never inflate (STRATEGY §6; Gate C).** Re-score the
> *verified* chain to what survives the cap (guest-root-only, migration-source-only, trusted-peer-only →
> typically Low / informational / out-of-scope), then file at the honest capped severity **or log it**.
> **MED is the default filing floor** — a sub-MED result is recorded in `PROGRESS.md`, not filed, unless
> the venue's rubric explicitly rewards a Low/Info. Relabelling a capped chain a crit is the fastest way
> to get a program to stop reading your reports.

Carve-outs feed two stages: the run-card threat-model filter (stage 0) and every finder's filter
(stage 3), so no finder burns budget inside an accepted-risk zone.

---

## 5 · Reachability discipline — prove the actor reaches the entry point (Gate A)

For this class reachability *is* half the severity (§1), so Gate A is where most finder claims die.
`entrypoints.sh` *(this round)* seeds the entry-point census — it enumerates the guest→host and
control-plane entries and the privilege each caller assumes:

- KVM `ioctl` handlers and the VM-exit / hypercall dispatch table,
- MMIO / PIO trap handlers that feed the instruction emulator,
- virtqueue / descriptor handlers (`vhost`) and `vsock` / socket listeners,
- confidential-computing secure-call / GHCB handlers,
- serving control-plane sockets (§3).

Treat its output as **leads to source-verify, never proof** (as with every census script). For each
candidate, answer three questions and verify every one at the pinned sha:

1. **Which entry channel** carries the untrusted bytes? (ioctl / hypercall / MMIO trap / virtqueue /
   `vsock` / secure-call / control socket.)
2. **Who drives it?** (guest-unprivileged / guest-root / the VMM acting on guest-controlled state / a
   network peer on the control plane.) Map it to the tier table in §1.
3. **Under what preconditions?** Registered and reachable under **default config**, or gated behind a
   non-default device, a feature flag (nested virt is often off by default), or a CoCo mode that must be
   enabled? Each precondition is a severity tax.

The data path from the guest-controlled bytes to the sink must be **unbroken** — no validation, clamp,
capability check, or type check skipped over, and no guard that actually lives on a caller / parent /
config default. **An unproven path is a *lead*, not a finding.** If any hop *or* the reachability
argument cannot be source-verified, demote it to `LEAD` in `PROGRESS.md` and do not submit — that is
Gate A, and it is the FINDER-PROMPT's reachability bar at stage 3.

---

## 6 · Incomplete-fix / variant analysis across arch siblings

The highest-EV source-review move in this class (STRATEGY §3c). A kernel/hypervisor patch typically
closes **one** call path or **one** arch, not the root cause's siblings — and the siblings are
under-swept *by construction*, because everyone assumes the CVE closed the issue. `patch-variant.sh`
*(this round)* points at it: feed it a just-landed security patch and it extracts the changed symbol /
guard / shape and greps the arch and path siblings; [`scripts/sink-grep.sh`](../scripts/sink-grep.sh)`
native` seeds the copy / length-math sites.

Read the patch **and its regression test** — the test reveals exactly which path the maintainer
considered closed, and by omission which they didn't (`dup-check-notes.md` §5). Then check the sibling
axes specific to this class:

- **x86 ↔ arm64** (and **VMX ↔ SVM**, Intel ↔ AMD): the fix lands in one arch; the identical missing
  check lives in the other.
- **sync ↔ async**: fixed on the synchronous fault / ioctl path, untouched on the deferred-work /
  interrupt / completion / worker-thread path (where the UAF usually lives).
- **fast-path ↔ slow / fallback path**, **read ↔ write**, **large-page ↔ small-page**, **32- ↔ 64-bit
  guest**, one virtio queue ↔ its siblings.

> **Illustrative only.** A patch adds a bounds check in a page-table walk at
> `arch/x86/kvm/mmu/tdp_mmu.c:980`, but the identical walk on the arm64 side near
> `arch/arm64/kvm/mmu.c:640` is untouched — a *new* finding.

A sibling the fix missed is a **new** finding, filed as *"incomplete fix of `<CVE/GHSA>`"* — **not a
dup** (`dup-check-notes.md` §1, §5). But still dup-check the variant itself (`dup-scan.sh` *(this round)*
+ [`scripts/dup-check-notes.md`](../scripts/dup-check-notes.md), Gate B): confirm the sibling is not
*separately* already filed before you carry it to a SUBMISSION.

---

## 7 · Venue fit

Severity is what the *venue* rewards against *their* rubric, and the **report → working-PoC gap** is the
hidden cost (STRATEGY §4). For a guest→host memory-corruption chain that gap is **wide** — a
source-verified OOB write is a long way from a reliable escape (heap grooming, KASLR, chaining).
critlover delivers the verified *candidate*; the human weaponizes.

| Venue | In-scope here | Realistic ceiling | Report → working-PoC gap |
|---|---|---|---|
| **Google OSS VRP** | in-scope Google OSS — e.g. **gVisor**, **crosvm**, and KVM / kernel code *where the current program lists it* | scales with severity + project tier; a guest→host escape in an in-scope project is top-tier | **moderate–wide** — needs the project in scope and a convincing impact case |
| **ZDI** | enterprise hypervisors / VMMs | higher cash ceilings | **wide** — generally expects a reproducible / working PoC (the **human** builds it) |
| **Kernel CNA / vendor GHSA / `SECURITY.md`** | upstream KVM and vendor kernels | a CVE + credit; cash rare | **narrow** — a clear, source-verified report *is* the deliverable |

**This is a stage-0 task, not a memory lookup.** Scope and ceilings move constantly:

- **Confirm the project is in scope on the current program page before hunting. An out-of-scope project
  = EV 0** — do not burn a run on a hypervisor no program covers. Upstream Linux KVM in particular may
  route through the **kernel CNA / a kernel-specific program** rather than a Google OSS VRP submission;
  decide the lane at stage 0 and record it in the `PROGRESS.md` run card.
- **Realistic per-bug ceiling:** a source-verified guest→host chain is a strong *candidate*, not a filed
  escape. Score the honest severity after the reachability tax (§1) and the carve-out test (§4), and
  budget the weaponization gap *before* fan-out, not after. **Never claim a "VM escape" you have not
  built** — the lane split in [`templates/SUBMISSION.md`](../templates/SUBMISSION.md) keeps the
  source-review chain and the human's authorized-lab validation separate.

Match the vein to the venue: guest→host memory corruption → OSS VRP (if in scope) / ZDI; control-plane
deserialization (§3) → huntr / vendor GHSA (see [`playbooks/ml-serving.md`](ml-serving.md) §6 and
STRATEGY §4).

---

## 8 · Stage-by-stage checklist (stages 0–5)

- **0 · Target & venue.** Pick the venue (OSS VRP / ZDI / kernel CNA / vendor GHSA) and **confirm the
  project is in scope — out-of-scope = EV 0** (§7). Read the rubric and the threat model; record the
  carve-outs **verbatim** (local-only, guest-root, trusted-cluster / trusted-migration) in the
  [`templates/PROGRESS.md`](../templates/PROGRESS.md) run card. → §1, §4, §7.
- **1 · Scope & scout.** [`scripts/clone.sh`](../scripts/clone.sh) (blobless + sparse) the subsystem
  subtree; [`scripts/churn.sh`](../scripts/churn.sh)` --days 90` for the freshest subsystem (CoCo
  first); `entrypoints.sh` *(this round)* to map the guest→host and control-plane entries and their
  tier. Note the incomplete-fix watch: a recent KVM CVE + the arch / path sibling to check (§6). Pin the
  sha — every `file:line` you later cite must be true at it.
- **2 · Bucket design.** One bucket per subsystem from the §2 taxonomy (CoCo → MMU/EPT → emulator →
  nested → vhost/vsock), plus a **control-plane deserialization** bucket (§3) if the target ships one.
  Seed one specific crit hypothesis + a reachability tier (§1) per bucket, *around* the carve-outs (§4).
- **3 · Fan-out finders.** One finder per bucket via
  [`.claude/workflows/crit-hunt.js`](../.claude/workflows/crit-hunt.js) with the SKILL's FINDER-PROMPT,
  each carrying the threat-model filter (the verbatim carve-outs), the **guest-reachability bar** (§5),
  and the dup-check duty. **Finders report chains, not exploits.**
- **4 · Honest grading (three gates).** **A** source-verify every hop *and the reachability* at the
  pinned sha (§5) · **B** dup-check against advisories + kernel git history + open PRs / issues
  (`dup-scan.sh` *(this round)* + [`scripts/dup-check-notes.md`](../scripts/dup-check-notes.md)) and run
  the incomplete-fix variant check (`patch-variant.sh` *(this round)*, §6) · **C** recalibrate against
  the vendor's own precedent and apply the carve-out test (§4). Keep survivors only; log the overclaim
  tally. MED floor.
- **5 · Write-up & journal.** One [`templates/SUBMISSION.md`](../templates/SUBMISSION.md) per survivor —
  the chain as *real* `file:line` hops at the sha, the reachability tier, the dup-check trail, the
  vendor-precedent severity, and a **non-functional trigger outline (no PoC, no payloads)**. Update the
  `PROGRESS.md` journal with every drop and *why*.

**Stop / pivot (STRATEGY §6):** retire a bucket after **N = 2** dry finder passes; on a hardened
flagship (upstream KVM) **K = 1** — if the first honest round is dry, the ceiling is real, so pivot to a
fresher subsystem or leave.

---

*Part of [critlover](../README.md). Siblings: [`playbooks/vmm-devices.md`](vmm-devices.md) (userspace
VMM device models), [`playbooks/ml-serving.md`](ml-serving.md) (the deserialization vein). Doctrine:
[`strategy/STRATEGY.md`](../strategy/STRATEGY.md) (§1 ceiling · §2 carve-outs · §3 veins · §4 venues ·
§5 overclaim tax · §6 stop/pivot). Runbook:
[`.claude/skills/crit-hunt/SKILL.md`](../.claude/skills/crit-hunt/SKILL.md).*

**One line to remember:** the guest is the attacker and a guest→host escape is a crit by default — so
the whole game is *reachability* (prove an unprivileged guest, or a low-trust control-plane peer,
reaches the ioctl / hypercall / ring / socket) and *novelty* (the arch / path sibling the last fix
missed), graded honestly around the local-only / guest-root / trusted-cluster carve-outs.
