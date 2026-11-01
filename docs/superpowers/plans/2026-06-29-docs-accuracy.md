# Documentation Accuracy Pass — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `README.md` and `ARCHITECTURE.md` truthful — correct the false opcode count, GPU-mining and privacy claims, and add an honest implementation-status section.

**Architecture:** Pure documentation edits. No code. Each claim is corrected against the source file that proves the real value. A single new "Implementation Status / Known Limitations" section is added to README.

**Tech Stack:** Markdown only.

**Spec:** `docs/superpowers/specs/2026-06-29-docs-accuracy-design.md`

---

### Task 1: Correct opcode count in README.md

**Files:**
- Modify: `README.md:18`, `README.md:109`, `README.md:243`

- [ ] **Step 1: Fix the Key Specifications table row (line 18)**

Replace:
```markdown
| **Smart Contracts** | ShadowVM (90+ opcodes, deterministic, gas-metered) |
```
With:
```markdown
| **Smart Contracts** | ShadowVM (52 opcodes, v1 consensus set, deterministic, gas-metered) |
```

- [ ] **Step 2: Fix the Project Structure comment (line 109)**

Replace:
```markdown
|   +-- vm/                   ShadowVM (90+ opcodes, U256, gas, precompiles)
```
With:
```markdown
|   +-- vm/                   ShadowVM (52 opcodes v1, U256, gas, precompiles)
```

- [ ] **Step 3: Fix the Architecture Overview box (line 243)**

Replace:
```markdown
| Runtime: ShadowVM (90+ opcodes), Event Bus          |
```
With:
```markdown
| Runtime: ShadowVM (52 opcodes v1), Event Bus        |
```

- [ ] **Step 4: Verify against source**

Run: `grep -c "OpCode::" runtime/vm/core/v1_spec.rs` and confirm the v1 set is 52 (per spec audit). Confirm no remaining "90+" in README:
Run: `grep -n "90+" README.md`
Expected: no output.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "docs: correct opcode count 90+ -> 52 (v1 consensus set) in README"
```

---

### Task 2: Correct opcode count in ARCHITECTURE.md

**Files:**
- Modify: `ARCHITECTURE.md:168`

- [ ] **Step 1: Fix the ShadowVM architecture bullet (line 168)**

Replace:
```markdown
- 90+ opcodes in 16 categories
```
With:
```markdown
- 52 opcodes in 16 categories (v1 consensus set; `runtime/vm/core/opcodes.rs`
  contains a larger 119-entry reference enum that is explicitly NOT the consensus
  set — see its file header)
```

- [ ] **Step 2: Verify**

Run: `grep -n "90+" ARCHITECTURE.md`
Expected: no output.

- [ ] **Step 3: Commit**

```bash
git add ARCHITECTURE.md
git commit -m "docs: correct opcode count and clarify non-consensus enum in ARCHITECTURE"
```

---

### Task 3: Clarify GPU mining status

**Files:**
- Modify: `README.md:21`, `ARCHITECTURE.md` (Section 4, GPU area)

- [ ] **Step 1: Fix README mining row (line 21)**

Replace:
```markdown
| **Mining** | ShadowHash (ASIC-resistant, 256KB scratchpad) |
```
With:
```markdown
| **Mining** | ShadowHash (ASIC-resistant, 256KB scratchpad). GPU miners currently run on CPU via Rayon — see Implementation Status |
```

- [ ] **Step 2: Add GPU note to ARCHITECTURE.md Section 4**

Locate Section 4 "Mining" (`grep -n "## 4. Mining" ARCHITECTURE.md`). Immediately
after the ShadowHash table, add:
```markdown
> **GPU status:** `engine/mining/gpu/cuda_miner.rs` and `opencl_miner.rs`
> currently parallelize on CPU via Rayon. There are no CUDA/OpenCL kernels or
> device bindings yet, so they provide no GPU speedup.
```

- [ ] **Step 3: Verify the claim against source**

Run: `grep -n "into_par_iter" engine/mining/gpu/cuda_miner.rs engine/mining/gpu/opencl_miner.rs`
Expected: matches present (confirms CPU/Rayon path).

- [ ] **Step 4: Commit**

```bash
git add README.md ARCHITECTURE.md
git commit -m "docs: clarify GPU miners run on CPU (no CUDA/OpenCL kernels)"
```

---

### Task 4: Clarify privacy status

**Files:**
- Modify: `README.md:17`, `ARCHITECTURE.md` (Section 8, Privacy)

- [ ] **Step 1: Fix README privacy row (line 17)**

Replace:
```markdown
| **Privacy** | CLSAG Ring Signatures + Pedersen Commitments + Stealth Addresses + Dandelion++ |
```
With:
```markdown
| **Privacy** | CLSAG Ring Signatures + Pedersen Commitments + Stealth Addresses + Dandelion++ (primitives implemented; end-to-end RingCT not yet enabled in consensus — see Implementation Status) |
```

- [ ] **Step 2: Add privacy status note to ARCHITECTURE.md Section 8**

Locate Section 8 "Privacy" (`grep -n "## 8. Privacy" ARCHITECTURE.md`). After the
privacy layer table, add:
```markdown
> **Status:** The privacy primitives above are implemented and unit-tested, but
> confidential transactions are **not yet accepted by consensus** —
> `engine/privacy/ringct/ring_validator.rs` performs structural checks only and
> rejects confidential TXs. End-to-end RingCT wiring is in progress.
```

- [ ] **Step 3: Verify the claim against source**

Run: `grep -n "CLSAG_NOT_WIRED\|return false" engine/privacy/ringct/ring_validator.rs | head`
Expected: the rejection gate is present.

- [ ] **Step 4: Commit**

```bash
git add README.md ARCHITECTURE.md
git commit -m "docs: clarify confidential TXs not yet accepted by consensus"
```

---

### Task 5: Add "Implementation Status / Known Limitations" section to README

**Files:**
- Modify: `README.md` (insert new section before `## License`)

- [ ] **Step 1: Insert the status section**

Locate the `## License` heading (`grep -n "## License" README.md`). Immediately
BEFORE it, insert:

```markdown
## Implementation Status / Known Limitations

Honest snapshot of what is wired vs. in progress (as of 2026-06-29):

| Area | Status |
|------|--------|
| Consensus / GHOSTDAG / DAG | Implemented, tested |
| Storage (RocksDB, WAL, atomic) | Implemented |
| Mempool (RBF / CPFP / surge pricing) | Implemented |
| P2P networking | Implemented (thread-per-peer; no TLS; ~1k peer ceiling) |
| ShadowVM (52 opcodes, v1) | Implemented |
| Mining (ShadowHash + Stratum pool) | Implemented |
| GPU mining | CPU fallback only — no CUDA/OpenCL kernels |
| Privacy primitives (CLSAG / Pedersen / range proofs / stealth) | Implemented (unit-tested) |
| Privacy in consensus (RingCT end-to-end) | Not yet enabled — confidential TXs rejected |
| HD wallet (BIP39 + SLIP-0010) | In progress |

```

- [ ] **Step 2: Verify**

Run: `grep -n "Implementation Status / Known Limitations" README.md`
Expected: one match, located before the License section.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add Implementation Status / Known Limitations section"
```

---

## Notes for executor

- This plan is documentation-only; there are no automated tests. "Verification"
  in each task means running the cited `grep` and confirming the corrected text
  matches the source-of-truth file.
- After Track C (RingCT phase 1) lands, the privacy rows here must be updated to
  "enabled". After Track B (HD wallet) lands, update that row to "Implemented".
  These follow-up edits are intentionally out of scope for this plan.
