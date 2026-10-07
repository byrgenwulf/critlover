# critlover — PLAYBOOK: VMM / device emulators (C)

*Target-class playbook for QEMU-style hypervisors and the device models they emulate (C). It
specializes the canonical pipeline (stages 0–5; `.claude/skills/crit-hunt/SKILL.md`) for the
**guest→host** trust boundary: which device bugs source review can actually prove, which eligibility
gates cap a chain before you start, how to bucket by device family, and which carve-outs to attack
*around*. Doctrine it builds on: `strategy/STRATEGY.md` §1–§6.*

> **Authorized, in-scope targets only; responsible disclosure via the official program.** Honor the
> vendor's published threat model and device-eligibility carve-outs — attack *around* them, never
> report *into* accepted behavior. **Report the chain, not an exploit:** no working VM-escape PoC, no
> payloads, no gadget chains — a human validates in an authorized lab and files. Honest grading over
> volume (STRATEGY §5): a correctly discarded finding is a win.

---

## 1 · Is this your lane?

Device models are **unusually source-reviewable** for native code: the guest→host boundary is explicit
(MMIO / PIO / DMA / virtqueue reads are the untrusted source), and the dangerous mistakes live in
control and data flow — you can *read* them without a fuzzer.

**In this lane (source review proves the chain):**
- **Bounds** — a guest-controlled length / offset / index reaching a copy or array access with the
  check missing or wrong. `scripts/sink-grep.sh <path> native` (memcpy / memmove / alloca / strcpy) is
  your first census; whether the size argument is guest-controlled is the manual delta that *is* the
  finding.
- **State-machine** — an operation accepted in a state the hardware spec forbids (reset / unplug /
  feature-negotiation order), or a **double-fetch / TOCTOU** on a value re-read from guest memory.
- **Use-after-free / re-entrancy** — a request freed on one path and completed on another; a device
  callback that re-enters while an object is mid-teardown (unplug, bus reset, async completion).
- **Logic** — a path- / id- / permission mistake in the emulated protocol (9pfs path handling,
  resource-id reuse).
- **Incomplete-fix variants** (§6) — the highest-EV move in this class (`scripts/patch-variant.sh`).

**Different lane (be honest — not critlover's deliverable):**
- **Raw memory-corruption-by-fuzzing.** Crashes found only by coverage-guided fuzzing of the emulated
  hardware state space (deep state interactions, allocator-dependent corruption, rare races) are a
  *fuzzing* lane — and the vendor usually runs their own device fuzzers, so dup risk is high and the
  readable edge is gone. If you cannot read the bug *as a chain*, it belongs to the fuzzing lane.
- **Weaponization.** Turning a source-verified OOB write into a reliable escape is the Pwn2Own-tier
  lane (§7). critlover stops at the verified chain.

> Your edge over the vendor's fuzzers is the **readable** logic / bounds / state / UAF bug and the
> **incomplete-fix sibling** — not racing the fuzzer on raw corruption (STRATEGY §1, §3c).

---

## 2 · Read the vendor's OWN eligibility gates FIRST (stage 0)

Before any churn or fan-out, these projects publish **gates that cap whole classes of chains before you
start.** Read them at stage 0, record them verbatim in the run card of `templates/PROGRESS.md`, and
confirm the family you intend to hunt clears them — otherwise you are hunting inside a carve-out for
EV 0.

- **Per-device-type security annotation.** The project marks which device models are
  *security-supported* (the untrusted-guest-safe set). **Only annotated device types are eligible.** A
  flawless chain in a non-annotated legacy / convenience device is **out of scope** — unless you can
  drive untrusted guest input *into* an annotated type (STRATEGY §2, the "only annotated types are
  CVE-eligible" row).
- **Accelerated (KVM / hardware-virt) vs software emulation.** The security boundary is the
  **accelerated** configuration. **Only the accelerated path is in scope**; a bug reachable only under
  pure software CPU emulation (TCG) is capped (§4).

> **Illustrative only.** The same descriptor-length mistake at `vmm/devices/virtio/blk.c:412` (an
> annotated, KVM-reachable device) is a finding; at `vmm/devices/legacy/parport.c:88` (a non-annotated
> convenience device) it is capped before you write the first finder. Same root cause, opposite
> verdict — the eligibility gate decides.

Capped before you start = **do not spend a finder on it.** Log the gate in `PROGRESS.md` and point the
budget at an eligible family.

---

## 3 · Bucket taxonomy by device family

One bucket per device family (stage 2); each carries its **dominant bug class** and a **reachability
tier** (§5). Seed one *specific* hypothesis per bucket — never "look for bugs." Confirm each family is
eligible (§2) before spending a finder on it.

| Bucket (device family) | Dominant bug class | Typical tier | Seed hypothesis (illustrative) |
|---|---|---|---|
| **virtio** (blk / net / gpu + vring core) | virtqueue descriptor handling — bounds / index on the ring, length double-fetch, split-vs-indirect descriptor confusion | guest-unpriv | guest-controlled descriptor `len` reaches a copy in `vmm/devices/virtio/vring.c:###` with no cap |
| **USB** (xHCI / EHCI + HID / storage / MTP) | transfer-descriptor length bounds; endpoint state-machine; UAF on unplug / reset re-entrancy | guest-unpriv | TD packet length unchecked before copy in `vmm/devices/usb/xhci.c:###` |
| **block / NVMe / SCSI** | LBA / length bounds math; PRP- / SG-list parsing; request-lifecycle UAF (async completion) | guest-unpriv | PRP-list walk overruns in `vmm/devices/nvme/prp.c:###` |
| **net** | packet-parse bounds (header len, offload offsets); RX / TX re-entrancy; fragment-reassembly math | guest-unpriv (or network via the backend) | checksum-offset math OOB in `vmm/devices/net/virtio_net.c:###` |
| **9pfs** | path-traversal / symlink logic; 9P message length / offset bounds; fid-lifecycle UAF | guest-unpriv | fid reused after clunk in `vmm/devices/9p/fid.c:###` |
| **display / GPU** (vga, virtio-gpu, 3d / virgl) | 2D / 3D command-stream bounds (blit / transfer rects); surface-dimension integer overflow; resource-id UAF | guest-unpriv | transfer-rect dims overflow surface alloc in `vmm/devices/display/gpu_2d.c:###` |
| **char / VNC / SPICE** | protocol-parse bounds **pre-auth**; state-machine before auth completes; UAF / double-free on client disconnect | **network pre-auth** | client-supplied length read before auth in `vmm/devices/char/vnc_proto.c:###` |
| **migration / snapshot** | VMState load-handler bounds (deserialization-shaped) | *source-trusted (capped) — see §4* | load handler trusts stream field length in `vmm/migration/vmstate_load.c:###` |

The **char / VNC / SPICE** bucket is the network-reachable **pre-auth** vein (STRATEGY §3b) — weight it
heavily. The **migration** bucket is mostly capped by a carve-out (§4) unless you reach the load path
from an untrusted source.

---

## 4 · Carve-outs — attack *around*, never *into*

These projects fence their boundaries in public. A chain that lands inside one is worth **zero**
(STRATEGY §2). The move is never to argue — it is to reach the **same bug class** from an **untrusted
source**, a **declared boundary**, or a **guest-unprivileged** actor.

| Carve-out (generic shape) | What it excludes | Attack *around* it |
|---|---|---|
| "Software-emulation (TCG) bugs are not security bugs." | Anything reachable only on the pure software CPU-emulation path. | The same bug class in a **device model reached under the accelerated (KVM) configuration** — the declared boundary (§2). |
| "vhost-user / vfio-user backends are not a security boundary." | A compromised *backend* process attacking the VMM (the backend is trusted, by design out-of-process). | The same corruption driven from the **guest** (untrusted) through the in-process device model, or where guest bytes cross into the control plane the VMM *itself* parses. |
| "Malicious migration / snapshot streams are out of scope (source trusted)." | Bugs that only fire from a crafted migration / snapshot stream. | The same corruption reached from an **untrusted source** — guest I/O or network — that doesn't depend on the trusted migration path. |
| "Guest-triggered host memory-allocation DoS is excluded." | Resource exhaustion / OOM from the guest. | An OOB **write / read**, type confusion, or **UAF** in the same path — a bug class the DoS exclusion doesn't cover. |
| "Nested L2→L1 escape is not a boundary (L0→host is)." | An escape from a nested guest into its guest-hypervisor parent. | The same bug class as **L0→host** — a device the top-level VMM emulates, reachable from the guest it actually isolates. |
| "Guest-root-only triggers are self-inflicted." | Anything needing root / kernel inside the guest. | The same sink reached **guest-unprivileged** (an unprivileged guest actor driving the device) or **network-reachable**. |

Carve-outs feed two stages: the run-card threat-model filter (stage 0) and every finder's filter
(stage 3), so no finder burns budget inside an accepted-risk zone.

---

## 5 · Reachability tiers — the tier *is* half the severity

"Who can trigger it" is half of severity (STRATEGY §3b), and Gate C taxes every precondition. The
*same* OOB write is a different finding at each tier:

| Tier | Who triggers | Gate-C effect |
|---|---|---|
| **network pre-auth** (VNC / SPICE / char over TCP, before auth) | anyone who can reach the port | **highest** — reach drops to "on the network"; a serious-impact bug here clears the CRIT bar |
| **guest-unprivileged** | any code in the guest, incl. a container / sandbox tenant or unprivileged userspace | **high** — the canonical guest→host escape tier; this is where device crits live |
| **guest-root** | root / kernel inside the guest (programs device MMIO / PIO directly) | **capped** — the "self-inflicted" carve-out (§4); downgrade hard unless you can re-reach it unprivileged |

Tag every bucket (§3) and every survivor (`templates/SUBMISSION.md`) with its tier, and apply the
**reachability tax** at Gate C: a chain that needs guest-root, a non-default device, or a second
unproven bug is **not** a CRIT no matter how clean the corruption. Default-skeptical; a tie between two
tiers → the lower (STRATEGY §5). **MED is the filing floor** — a capped sub-MED result is logged in
`PROGRESS.md`, not filed, unless the venue's rubric explicitly rewards it.

---

## 6 · Incomplete-fix / variant analysis (the strongest move here)

Device models are patched one call path at a time; the root cause's siblings are under-swept *by
construction* (STRATEGY §3c). This is the highest-EV source-review move in this class. Read the fix
diff **and its regression test** — the test shows exactly which path the maintainer considered closed,
and, by omission, which they didn't — then grep the sibling shape. `scripts/patch-variant.sh` does the
diff-read-and-grep; `scripts/sink-grep.sh <path> native` seeds the copy sites.

The four variant shapes to check on every device CVE:
- **Adjacent handler** — the fix hardened virtio-blk's descriptor loop; the identical mistake sits
  untouched in virtio-net's.
- **Sync vs async** — bounds added on the synchronous submit path but not the **async completion**
  callback (where the UAF lives).
- **Header vs trailer** — a length check added when parsing a packet / descriptor **header** but not
  its **trailer / footer**.
- **Read vs write** — the guard covers the guest-**read** direction but the guest-**write**
  (DMA-into-guest) direction still overruns.

> **Illustrative only.** A patch adds a cap in `parse_desc_header()` at `vmm/devices/virtio/vring.c:120`,
> but the identical unchecked length lives in `parse_desc_trailer()` at `vmm/devices/virtio/vring.c:188`,
> untouched. File it as *"incomplete fix of `<CVE/GHSA>`"*, not a dup — then dup-check the variant
> itself (`scripts/dup-check-notes.md` §5).

---

## 7 · Venue fit

Severity is what the *venue* rewards against *their* rubric, and the **report → working-PoC gap** is the
hidden cost (STRATEGY §4). For VMM memory-corruption chains that gap is **wide**: a source-verified OOB
write is a long way from a reliable escape (heap grooming, ASLR, chaining). Pick the venue that pays for
what critlover actually delivers — a verified chain.

| Venue | Fit for a source-verified VMM chain | Report → working-PoC gap |
|---|---|---|
| **Vendor advisory process** (GHSA / `SECURITY.md` / the project's security list) | **Best fit.** A clear, source-verified chain → CVE + credit. Reputation currency. | **Narrow** — the verified report *is* the deliverable. |
| **ZDI** (year-round) | Good fit for a *candidate*; higher cash ceilings on hypervisor targets. | **Wide** — generally expects a reproducible / working PoC. critlover gets you the candidate; the human weaponizes — budget for it. |
| **Pwn2Own-tier** (working full VM escape) | **Separate lane — not critlover's output.** Specific targets / dates, a reliable chained escape required. | n/a — this *is* the weaponization lane. |

So: file the **source-verified chain to the vendor** for the CVE; hand **ZDI a candidate** only with
eyes open about the gap; **never claim a "VM escape" you have not built.** The validation lane (building
and running the PoC in an authorized lab) is the human's, per the lane split in
`templates/SUBMISSION.md`.

---

## 8 · Stage-by-stage checklist (stages 0–5)

- **0 · Target & venue.** Read the eligibility gates (§2: security-annotated device set;
  accelerated-vs-software scope) **and** the carve-outs (§4). Pick the venue (§7). Record all of it
  verbatim in the `templates/PROGRESS.md` run card. Confirm your intended family is eligible — else
  pivot now.
- **1 · Scope & scout.** `scripts/clone.sh` the device-model subtree; `scripts/churn.sh --days 90` for
  the freshest / least-swept device (new model, recent refactor); `scripts/entrypoints.sh` to map the
  MMIO / PIO / virtqueue / DMA entry points and their tier; note any just-patched device CVE for the §6
  watch. Pin the sha — every `file:line` you later cite must be true at it.
- **2 · Buckets.** One bucket per **eligible** device family (§3), tagged with dominant bug class +
  reachability tier (§5); seed one specific hypothesis each, *around* the carve-outs (§4), never into
  them.
- **3 · Fan-out.** One finder per bucket via `.claude/workflows/crit-hunt.js` with the SKILL's
  FINDER-PROMPT. Filter = §4 carve-outs; reachability bar = guest-unpriv / network-pre-auth preferred.
  `scripts/sink-grep.sh native` + `scripts/patch-variant.sh` seed the leads. **Chains, not exploits** —
  source → transform → sink as `file:line` hops at the pinned sha.
- **4 · Honest grading (three gates).** **A** source-verify every hop (the read is really
  guest-controlled; the bound is really absent / wrong; the sink really corrupts). **B** dup-check
  (`scripts/dup-check-notes.md` / `scripts/dup-scan.sh`) — device CVEs are dense: CVE / GHSA / OSV + the
  project's security list + open PRs / issues on *that* device, plus the §6 incomplete-fix test. **C**
  recalibrate: carve-out test (§4 — TCG? backend? migration-only? DoS-only? L2→L1? guest-root-only?) +
  reachability tax (§5). MED floor.
- **5 · Write-up & journal.** One `templates/SUBMISSION.md` per survivor — chain, reachability tier, dup
  trail, vendor-precedent severity, and the lane split (source review done; the working PoC is the
  human's authorized-lab job). Update the `templates/PROGRESS.md` journal and the overclaim tally.

---

**One line to remember:** the device model is a *readable* boundary — hunt **eligible** families for
**guest-unprivileged / pre-auth** bounds · state · UAF bugs, attack *around* the TCG / backend /
migration / DoS / nesting / guest-root carve-outs, lean on **incomplete-fix variants**, and file the
**verified chain** — not a VM escape you haven't built.
