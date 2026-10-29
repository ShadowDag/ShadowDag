# Design: Documentation Accuracy Pass

**Date:** 2026-06-29
**Track:** A (of 3 parallel tracks: docs / HD wallet / RingCT phase 1)
**Status:** Approved (design), pending spec review

## Problem

`README.md` and `ARCHITECTURE.md` make claims that do not match the code, creating
a credibility/legal risk if the project is published or shown to third parties.
Confirmed mismatches (from code audit):

1. **Opcode count** — Docs say "90+ opcodes". The live v1 consensus set is **52
   opcodes** (`runtime/vm/core/v1_spec.rs`). A parallel 119-entry enum exists in
   `runtime/vm/core/opcodes.rs` but its own header explicitly warns it is **NOT**
   the consensus set.
2. **GPU mining** — Docs imply real CUDA/OpenCL acceleration. The "GPU" miners
   (`engine/mining/gpu/cuda_miner.rs`, `opencl_miner.rs`) actually run on **CPU via
   Rayon**; there are no GPU kernels or device bindings.
3. **Privacy** — Docs present CLSAG/Pedersen/stealth/Dandelion++ as shipped
   features. In reality confidential transactions are **rejected at consensus**
   today (`engine/privacy/ringct/ring_validator.rs` rejection gate); the crypto
   primitives exist but are not wired end-to-end.

## Goal

Make the two top-level docs truthful without gutting them: correct the specific
false numbers/claims inline, and add a single honest status section.

## Non-Goals

- No restructuring of the docs.
- No marketing rewrite.
- Not touching other docs (CHANGELOG, OPS_RUNBOOK, TESTNET_GUIDE) unless a
  corrected claim is duplicated there.

## Changes

### README.md
- Key Specifications table: `Smart Contracts` row "90+ opcodes" → "52 opcodes
  (v1 consensus set), deterministic, gas-metered".
- Mining row: keep ShadowHash description; remove any implication of GPU
  acceleration being functional. Point to status section.
- Privacy row: append "(primitives implemented; end-to-end RingCT in progress —
  see Implementation Status)".
- Add new top-level section **"Implementation Status / Known Limitations"** (see
  below).

### ARCHITECTURE.md
- Section 5 (ShadowVM): "90+ opcodes" → "52 opcodes (v1 consensus)"; add one line
  noting the 119-entry `opcodes.rs` enum is a non-consensus reference table.
- Section 4 (Mining): add a line under GPU that CUDA/OpenCL miners currently
  execute on CPU via Rayon (no GPU kernels yet).
- Section 8 (Privacy): add a status note that confidential TXs are not yet
  accepted by consensus.

### New "Implementation Status / Known Limitations" section (README)

A short table with honest per-area status:

| Area | Status |
|------|--------|
| Consensus / GHOSTDAG / DAG | Implemented, tested |
| Storage (RocksDB) | Implemented |
| Mempool (RBF/CPFP/surge) | Implemented |
| P2P networking | Implemented (thread-per-peer; no TLS; ~1k peer ceiling) |
| ShadowVM (52 opcodes) | Implemented |
| Mining (ShadowHash + Stratum) | Implemented |
| GPU mining | **CPU fallback only** (no CUDA/OpenCL kernels) |
| Privacy (CLSAG/Pedersen/stealth) | Primitives implemented; **RingCT not yet enabled in consensus** |
| HD wallet | In progress (BIP39 + SLIP-0010) |

## Sequencing note

Because this runs in parallel with the RingCT (Track C) and HD wallet (Track B)
work, the status section reflects reality **at time of writing**. After Track C
phase 1 lands (consensus verifies CLSAG), the privacy row must be updated; after
Track B lands, the HD wallet row must be updated. This is called out so the docs
update is not treated as "done forever."

## Testing / Verification

- Docs-only change; no code tests.
- Verification = re-read each corrected claim against the cited source file and
  confirm the number/statement matches.

## Risks

- Low. Worst case is a number still being slightly off; mitigated by citing the
  source file for each claim during implementation.
