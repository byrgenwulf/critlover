# critlover — playbooks

Target-class playbooks specialize the canonical pipeline (**stages 0–5**;
[`../.claude/skills/crit-hunt/SKILL.md`](../.claude/skills/crit-hunt/SKILL.md)) for one kind of target:
which buckets to expect, the signature sinks, the carve-outs vendors in that space publish and how to
attack *around* them, the reachability tiers, and which venue actually pays for what critlover delivers.
They don't replace the runbook or the doctrine ([`../strategy/STRATEGY.md`](../strategy/STRATEGY.md)) —
they tell you where the crits sit in *this* kind of code. Pick the one that fits your target at
**stage 0**, then run the normal pipeline.

| Playbook | Target class | The vein it's built around |
|---|---|---|
| [`ml-serving.md`](ml-serving.md) | ML-serving / LLM-inference frameworks (Python / FastAPI / async-RPC): inference servers, model gateways, agent/tool platforms, RAG backends | network-reachable deserialization + fresh routers/connectors, around the trusted-network / model-file carve-outs |
| [`vmm-devices.md`](vmm-devices.md) | VMM / device emulators (C; QEMU-style) — the **userspace** device models | guest→host bounds / state-machine / UAF in *eligible* device families, around the TCG / backend / migration / DoS / guest-root carve-outs |
| [`kvm-kernel.md`](kvm-kernel.md) | The **in-kernel** hypervisor (KVM) + distributed-serving control planes | guest→host memory corruption in the freshest subsystems (confidential computing first) + the control-plane deserialization crossover |

All three share the same spine — the canon in [`../CLAUDE.md`](../CLAUDE.md): stages 0–5, the three
grading gates (**A** source-verify · **B** dup-check · **C** severity-recalibrate), the MED filing floor,
and "attack *around* the carve-outs, never *into* them." Every example in them is illustrative (fictional
`file:line`); none contains real target source or exploit code. `vmm-devices.md` (userspace device
models) and `kvm-kernel.md` (the in-kernel lane) are deliberate siblings and cross-reference each other.

**Adding a playbook.** Copy the shape of an existing one: open with the responsible-disclosure
blockquote, then (1) why the class yields crits / is this your lane, (2) a bucket taxonomy as
`PROGRESS.md` rows, (3) the signature sinks tied to [`../scripts/sink-grep.sh`](../scripts/sink-grep.sh),
(4) the class's recurring high-severity vein, (5) the carve-outs + attack-around moves, (6) venue fit,
(7) a stage-by-stage (0–5) checklist mapping to the recon scripts. Keep the canon vocabulary and the
illustrative-only rule, and add a row to the table above.
