# ShadowDAG — External Cryptography & Consensus Audit Package

**Purpose:** hand this to the external cryptographer + consensus auditor. It lists (1) the code in scope, (2) the supporting documents, (3) the specific questions to answer, (4) the test-vectors/KATs to demand, and (5) where formal verification / a professional firm is warranted.

**Chain summary:** hybrid chain — EVM execution (ShadowVM) + Monero-style RingCT privacy (Ristretto/curve25519-dalek) + Kaspa-style GHOSTDAG blockDAG + a custom memory-hard PoW (UmbraHash = SHA3 + Ethash-DAG + mini-ProgPoW). Rust. Branch: `feature/privacy-hdwallet-docs`.

**Standing rule:** the project owner requires this external sign-off **before mainnet**; the internal pre-audit (doc #4 below) only prepares and de-risks it — it does not certify the system.

---

## 1. Code in scope (exact paths, grouped by surface)

### A. Ring signatures (CLSAG / dual-key CLSAG)
- `engine/privacy/ringct/clsag.rs`
- `engine/privacy/ringct/dual_clsag.rs`   ← the LIVE confidential gate (`dual_clsag::verify`)
- `engine/privacy/ringct/ring_signature.rs`   ← legacy, believed dead — confirm it is not a consensus gate
- `engine/privacy/ringct/ring_validator.rs`

### B. Commitments, range proof, amount encoding
- `engine/privacy/confidential/pedersen.rs`   ← generators G, H (verify unknown dlog of H wrt G)
- `engine/privacy/confidential/range_proof.rs`   ← HAND-ROLLED Borromean/AOS per-bit proof (highest-risk primitive)
- `engine/privacy/ringct/amount_encoding.rs`

### C. Key image, ring validation, confidential consensus
- `engine/privacy/ringct/key_image.rs`
- `engine/privacy/ringct/confidential_consensus.rs`   ← `verify_confidential_tx` / `verify_shield_tx`
- `engine/privacy/ringct/tx_confidential.rs`   ← `parse_confidential_output` (input/output decoders)
- `engine/privacy/ringct/decoy.rs`   ← decoy selection (uniform — see Q4)
- `engine/privacy/ringct/scan.rs`, `engine/privacy/ringct/serialization.rs`

### D. Stealth addresses & view/spend keys
- `engine/privacy/stealth/stealth_address.rs`, `view_key.rs`, `stealth_scanner.rs`
- `domain/address/stealth_address.rs`, `domain/address/key_derivation.rs`

### E. Shield transaction (transparent -> confidential composition)
- `engine/privacy/ringct/builder.rs`
- `engine/privacy/ringct/confidential_consensus.rs`
- `domain/transaction/tx_validator.rs`, `domain/utxo/utxo_set.rs`, `domain/utxo/utxo_validator.rs`

### F. UmbraHash proof-of-work (custom composition — highest-risk PoW tier)
- `engine/mining/algorithms/umbrahash.rs`   ← core (epoch_seed, mkcache, dataset, hashimoto_light/full)
- `engine/mining/algorithms/hash_mix.rs`, `anti_asic.rs`, `shadowhash.rs` (legacy)
- `engine/mining/pow/pow_validator.rs`   ← version-gated dispatch + the activation floor
- `engine/mining/gpu/umbrahash.cl`, `engine/mining/gpu/umbra.rs` (GPU kernels — must match CPU byte-for-byte)

### G. Consensus / fork-choice adjacency (context for the above)
- `service/network/nodes/full_node.rs` (`recompute_virtual_chain`, apply paths)
- `engine/consensus/validation/block_validator.rs`, `engine/consensus/reorg/`

---

## 2. Supporting documents to send with the code
- `docs/AUDIT_SCOPE.md`
- `docs/superpowers/audits/2026-07-06-external-review-dossier.md`  (prior dossier)
- `docs/superpowers/audits/2026-07-05-shield-umbrahash-internal-review.md`  (shield + PoW internal review + 2 fixed DoS bugs)
- `docs/superpowers/audits/2026-07-15-internal-crypto-preaudit.md`  (**latest** — 12 confirmed findings, per-surface proven/assumed/unknown, and the source of the questions below)

---

## 3. Questions to put to the auditor

**PoW / mining economics**
1. **Single cost floor (findings F-1/F-2).** UmbraHash's mandatory-activation floor is currently inert (`UMBRA_ACTIVATION_HEIGHT = None` in `umbrahash.rs`), so cheap legacy ShadowHash is co-valid at the *same* difficulty target. Independently confirm ShadowHash provides ~zero memory-hardness (its scratchpad access pattern is not value-dependent → streamable → reduces to SHA256). **Is retiring ShadowHash entirely at the fork (one uniform floor) preferable to giving each algorithm its own retargeted difficulty domain? What exact activation-height + minimum-version-by-height rule closes the downgrade with no reorg-window ambiguity?**
2. **UmbraHash composition.** It composes SHA3-256/512 + the Ethash/Dagger-Hashimoto DAG + a mini-ProgPoW ALU layer. Confirm the memory-hardness reduces to the Ethash bandwidth-latency assumption, that `hashimoto_light == hashimoto_full` for **all** inputs (not just sampled), and that the CPU and GPU (OpenCL) paths are byte-identical.

**Privacy / RingCT**
3. **Range proof.** The Borromean per-bit range proof is hand-rolled. **Recommend replacing it with a vetted implementation (dalek Bulletproofs)?** Independently review its soundness (no negative/overflow amount can pass → no inflation) if it is kept.
4. **Degenerate-point rejection (F-9/F-4).** Should identity/degenerate points be rejected **uniformly** at every DH / key-image / ephemeral-R site? Please enumerate every `decompress()` that feeds a secret-scalar multiply and confirm each rejects the identity/torsion cases.
5. **Decoy distribution (F-7).** Decoys are drawn uniformly over the whole output index → temporal bias (newest ring member is disproportionately the real spend). Validate a gamma/log-normal spend-age model; **should consensus bound ring-member age at all?**

**Consensus determinism / DoS**
6. **Cross-architecture determinism (F-5).** Audit **all** consensus-critical hash preimages for platform-width or endianness-dependent encodings (`usize`, `to_le_bytes`/`to_ne_bytes` on `usize`, pointer-width casts). Require a fixed-width-encoding invariant + a 32-bit vs 64-bit differential test. (One instance fixed in `range_proof.rs`; ask them to find the rest.)
7. **Pre-validation resource bounds (F-3).** Confirm a **tip-relative** height/epoch bound before any `epoch_seed`/`mkcache` work on an unvalidated header, and review every unvalidated-header admission path (relay / sync / light node) for pre-PoW CPU/memory amplification.

**Shield composition**
8. **Value conservation.** Confirm the transparent→confidential shield binds the public input amount `A` to the commitment `C = A·H + r·G` with no mint path, and that the dual-bucket (transparent supply / confidential supply) accounting conserves total supply across apply **and** reorg/rollback.

---

## 4. Test-vectors / KATs to demand (deliverables from the auditor or to build before mainnet)
- **UmbraHash:** published KAT vectors for `epoch_seed`, `mkcache`, `calc_dataset_item`, and full `hashimoto_light`/`hashimoto_full` at fixed (height, header, nonce); a `light == full` differential fuzzer; a build-determinism KAT.
- **Range proof:** boundary vectors (v = 0, 1, 2^63, 2^64−1, 2^64), a rejection KAT for an out-of-range commitment, and a **32-bit vs 64-bit reproducibility vector**.
- **dual-CLSAG / clsag:** sign/verify KATs at min & max ring size; identity-key-image rejection vector for **both** modules; a tamper suite (mutated ring member / commitment / pseudo-out).
- **Stealth:** an identity-R rejection vector; a full-32-byte (not 160-bit-truncated) ownership vector.

## 5. Where formal verification / a professional firm is warranted
- **Professional audit firm (hard gate before mainnet):** full RingCT primitive review incl. the hand-rolled Borromean range proof; constant-time verification of wallet signing (dudect/ctgrind); the UmbraHash composition + light==full equivalence.
- **Formal verification:** the shield/RingCT balance-and-range soundness reduction, and the PoW version-gate / single-cost-floor state machine (prove no height admits two algorithms at one target post-activation).
- **Tooling to run:** KAT/Wycheproof-style vectors, differential/property fuzzing (cryptofuzz-style), constant-time analysis on the binary, and a 32/64-bit differential build test.

---

*Prepared from the internal adversarial pre-audit (2026-07-15). Contains no secrets; defensive review of the owner's own authorized chain.*
