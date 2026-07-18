# ShadowDAG — External Cryptography & Consensus Audit Package

**Purpose:** hand this to the external cryptographer + consensus auditor. It lists (1) the code in scope, (2) the supporting documents, (3) the specific questions to answer, (4) the test-vectors/KATs to demand, and (5) where formal verification / a professional firm is warranted.

**Chain summary:** hybrid chain — EVM execution (ShadowVM) + Monero-style RingCT privacy (Ristretto/curve25519-dalek) + Kaspa-style GHOSTDAG blockDAG + a custom memory-hard PoW (UmbraHash = SHA3 + Ethash-DAG + mini-ProgPoW). Rust.

**AUDIT ANCHOR (frozen):** tag **`RC1-AUDIT-FREEZE`** → commit **`ad157eb6f19573ce2acdc587adae72b7ddd17d14`** on branch `feature/privacy-hdwallet-docs` (github.com/ShadowDag/ShadowDag). Audit THIS SHA, not the branch head. Freeze discipline is active: no cryptography/serialization/consensus change lands until this audit completes; any such change re-scopes the audit under a new tag. (The tag is annotated, not GPG-signed — verify by SHA.)

**Validation status at the frozen SHA (context, not certification):** full lib suite 2331 passed / 0 failed, clippy `-D warnings` clean; three internal adversarial review rounds on the M5 change (final round: all lenses pass); live verification on a fresh single-node regtest (past height 1, unclean-shutdown restart, both PoW preimages) and on a 3-node public testnet fleet running this SHA (fresh chain mined 36k+ blocks, hash-verified convergence across all nodes, zero `prev_state_commitment mismatch` over entire logs, follower restart + recovery under real P2P).

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
- `engine/mining/algorithms/umbrahash.rs`   ← core (epoch_seed, mkcache, dataset, hashimoto_light/full) + the network-aware activation schedule (`MAINNET_UMBRA_ACTIVATION_HEIGHT = Some(1)`, i.e. mainnet retires ShadowHash from height 1; testnet/regtest unscheduled) and the per-epoch build lock (H3)
- `engine/mining/algorithms/hash_mix.rs`, `anti_asic.rs`, `shadowhash.rs` (legacy algorithm + the ONE shared header-preimage serializer — see section H)
- `engine/mining/pow/pow_validator.rs`   ← version-gated dispatch + `validate_for_network` activation floor + tip-relative pre-cache bound (H3)
- `engine/mining/gpu/umbrahash.cl`, `engine/mining/gpu/umbra.rs` (GPU kernels — must match CPU byte-for-byte; the GPU nonce patch relies on `HEADER_NONCE_OFFSET`)
- Note: the built-in ShadowHash-only Stratum pool is force-disabled on ALL networks at the frozen SHA (`daemon/mod.rs`) — it is not a live mining surface; confirm it cannot be re-enabled into a rejectable-block producer.

### G. Consensus / fork-choice adjacency (context for the above)
- `service/network/nodes/full_node.rs` (`recompute_virtual_chain`, apply paths; M3 atomic acceptance via leaf-gated `ghostdag.remove_block` + `drop_offending_block_if_leaf`)
- `engine/consensus/validation/block_validator.rs`, `engine/consensus/reorg/`

### H. M5 deferred state commitment (NEW consensus + serialization surface at this freeze)
Every block header carries `prev_state_commitment` = SHA3-256 over a domain-separated encoding (`"ShadowDAG_PrevState_v1"`) of the block's GHOSTDAG selected parent; the value is inside BOTH PoW preimages (header domain tag bumped `ShadowDAG_Block_v1` → `_v2`) and is consensus-enforced for every height>0 block. At this freeze it binds ONLY the deterministic selected-parent identity — the parent's `utxo_commitment`/`state_root`/`receipt_root` slots are encoded as canonical `None` (reserved for a future deterministic-roots fork).
- `engine/mining/algorithms/shadowhash.rs`   ← `serialize_header_raw` (the single core preimage serializer, domain v2), `enc_opt_root` (canonical Option encoding: `0x00` vs `0x01||len||bytes`), `compute_prev_state_commitment`, `genesis_prev_state_commitment`, `HEADER_NONCE_OFFSET` invariant
- `domain/block/block_header.rs`   ← the header field (`#[serde(default)]`)
- `service/network/nodes/full_node.rs`   ← `expected_prev_state_commitment` (the ONE shared miner/validator derivation over `select_parent(parents)`), `publish_mining_template` / `republish_mining_template` (template publication: startup, per-accept, post-genesis, post-recovery), and the deferred-verify in BOTH accept paths (`process_block_inner` AND the orphan-reconnect `process_block_without_orphans`)
- `service/network/rpc/rpc_server.rs`   ← `getblocktemplate` serves it (process-default fallback when `RpcState.mining_state` is None); `cmd_submitblock` re-applies the submitted value before re-hash/validate
- `bin/miner.rs`   ← stamps the template value at every hash site (ShadowHash, UmbraHash, GPU) + transmits it on submit
- `config/genesis/genesis.rs`   ← genesis re-mined for the v2 preimage (new mainnet/testnet/regtest nonce+hash constants; mainnet build panics on any mismatch)

---

## 2. Supporting documents to send with the code
- `docs/AUDIT_SCOPE.md`
- `docs/superpowers/audits/2026-07-06-external-review-dossier.md`  (prior dossier)
- `docs/superpowers/audits/2026-07-05-shield-umbrahash-internal-review.md`  (shield + PoW internal review + 2 fixed DoS bugs)
- `docs/superpowers/audits/2026-07-15-internal-crypto-preaudit.md`  (12 confirmed findings, per-surface proven/assumed/unknown, and the source of most questions below)
- `docs/superpowers/audits/2026-07-15-final-reaudit.md`  (re-audit of the pre-audit fixes)
- `docs/superpowers/specs/2026-07-16-m5-deferred-state-commitment-design.md`  (**M5 design** — the deferred state commitment now in scope as section H)

---

## 3. Questions to put to the auditor

**PoW / mining economics**
1. **Single cost floor — now IMPLEMENTED, review the rule (was F-1/F-2).** Since the pre-audit, H2 landed: `umbra_activation_height(Mainnet) = Some(1)` (`umbrahash.rs`), enforced by `umbra_required_at_for` + `PowValidator::validate_for_network`, so mainnet retires ShadowHash from height 1 (genesis is the only ShadowHash block) while testnet/regtest remain unscheduled. **Review the implemented activation rule**: does the version-by-height gate close the cheap-algorithm downgrade with no reorg-window ambiguity (no height where both algorithms are co-valid at one target)? Is genesis-only ShadowHash acceptable? Also still confirm the underlying claim: ShadowHash provides ~zero memory-hardness (access pattern not value-dependent → streamable → reduces to SHA256).
2. **UmbraHash composition.** It composes SHA3-256/512 + the Ethash/Dagger-Hashimoto DAG + a mini-ProgPoW ALU layer. Confirm the memory-hardness reduces to the Ethash bandwidth-latency assumption, that `hashimoto_light == hashimoto_full` for **all** inputs (not just sampled), and that the CPU and GPU (OpenCL) paths are byte-identical.

**Privacy / RingCT**
3. **Range proof.** The Borromean per-bit range proof is hand-rolled. **Recommend replacing it with a vetted implementation (dalek Bulletproofs)?** Independently review its soundness (no negative/overflow amount can pass → no inflation) if it is kept.
4. **Degenerate-point rejection (F-9/F-4).** Should identity/degenerate points be rejected **uniformly** at every DH / key-image / ephemeral-R site? Please enumerate every `decompress()` that feeds a secret-scalar multiply and confirm each rejects the identity/torsion cases.
5. **Decoy distribution (F-7).** Decoys are drawn uniformly over the whole output index → temporal bias (newest ring member is disproportionately the real spend). Validate a gamma/log-normal spend-age model; **should consensus bound ring-member age at all?**

**Consensus determinism / DoS**
6. **Cross-architecture determinism (F-5).** Audit **all** consensus-critical hash preimages for platform-width or endianness-dependent encodings (`usize`, `to_le_bytes`/`to_ne_bytes` on `usize`, pointer-width casts). Require a fixed-width-encoding invariant + a 32-bit vs 64-bit differential test. (One instance fixed in `range_proof.rs`; ask them to find the rest.)
7. **Pre-validation resource bounds — now IMPLEMENTED, verify coverage (was F-3).** H3 landed a per-epoch build lock + a **tip-relative** orphan/height bound before `epoch_seed`/`mkcache` work. Verify the bound is enforced on EVERY unvalidated-header admission path (relay / sync / light node / RPC submit) and that no path still allows pre-PoW CPU/memory amplification (epoch-thrash, far-future height, parallel cache builds).

**Shield composition**
8. **Value conservation.** Confirm the transparent→confidential shield binds the public input amount `A` to the commitment `C = A·H + r·G` with no mint path, and that the dual-bucket (transparent supply / confidential supply) accounting conserves total supply across apply **and** reorg/rollback.

**M5 deferred state commitment (NEW at this freeze — section H)**
9. **Header-domain migration.** `serialize_header_raw` bumped its domain tag `ShadowDAG_Block_v1` → `_v2` (same 18-byte length, `HEADER_NONCE_OFFSET` unchanged) and appends `prev_state_commitment` via `enc_opt_root` after the sorted parents. Confirm: (a) no v1/v2 cross-domain preimage collision; (b) `enc_opt_root` is injective/canonical (`None` vs `Some("")` vs length-prefix games); (c) the appended field cannot create preimage ambiguity with any adjacent variable-length field; (d) the GPU nonce-patch offset remains sound.
10. **Commitment semantics & non-degradation.** At this freeze the commitment binds only `select_parent(parents)` — data already derivable from the PoW-bound parent list. Confirm this adds binding without weakening anything (no PoW-strength downgrade, no new grinding surface via the reserved all-`None` root slots), and state what invariants a future fork MUST satisfy before real roots are bound into the reserved slots (deterministic, populated pre-mine, reorg-independent).
11. **Enforcement completeness.** The deferred-verify runs in `process_block_inner` AND `process_block_without_orphans`. Adversarially confirm there is NO height>0 acceptance path (sync, relay, compact-block reconstruction, recovery/replay, RPC submit) that admits a block bypassing it, and that miner-side template publication (`publish_mining_template` on startup / per-accept / post-genesis / post-recovery) can never serve a (parents, commitment) pair the verifier rejects — three liveness-halt wirings of exactly this class were found and fixed internally (daemon null-fallback; fresh-genesis publish; restart stale-seed); hunt for a fourth.
12. **Genesis re-mine.** The v2 preimage required re-mining genesis (new mainnet/testnet/regtest nonce+hash constants; mainnet build hard-panics on mismatch). Confirm the constants reproduce from the committed code and that `genesis_prev_state_commitment()` (empty selected-parent) is unambiguous vs any real parent hash.

**Consensus atomicity (M3)**
13. **Atomic acceptance.** `recompute_virtual_chain` failure now rolls back the just-inserted block only when it is a childless leaf (`drop_offending_block_if_leaf`, leaf-gated `ghostdag.remove_block`). Confirm acceptance is all-or-nothing under every failure interleaving (no phantom GHOSTDAG tip with a deleted body, no half-deleted mid-chain block).

---

## 4. Test-vectors / KATs to demand (deliverables from the auditor or to build before mainnet)
- **UmbraHash:** published KAT vectors for `epoch_seed`, `mkcache`, `calc_dataset_item`, and full `hashimoto_light`/`hashimoto_full` at fixed (height, header, nonce); a `light == full` differential fuzzer; a build-determinism KAT.
- **Range proof:** boundary vectors (v = 0, 1, 2^63, 2^64−1, 2^64), a rejection KAT for an out-of-range commitment, and a **32-bit vs 64-bit reproducibility vector**.
- **dual-CLSAG / clsag:** sign/verify KATs at min & max ring size; identity-key-image rejection vector for **both** modules; a tamper suite (mutated ring member / commitment / pseudo-out).
- **Stealth:** an identity-R rejection vector; a full-32-byte (not 160-bit-truncated) ownership vector.
- **M5 commitment:** published vectors for `compute_prev_state_commitment` (empty selected-parent = the genesis constant; a known 64-hex parent; `None` vs `Some("")` root-slot discrimination); a v1-vs-v2 domain-separation vector (same fields, different digests); a header-preimage vector proving a 1-byte `prev_state_commitment` change flips both PoW preimages (the in-repo KAT `prev_state_commitment_binds_to_block_hash` is the starting point); genesis nonce/hash reproduction for all three networks.

## 5. Where formal verification / a professional firm is warranted
- **Professional audit firm (hard gate before mainnet):** full RingCT primitive review incl. the hand-rolled Borromean range proof; constant-time verification of wallet signing (dudect/ctgrind); the UmbraHash composition + light==full equivalence.
- **Formal verification:** the shield/RingCT balance-and-range soundness reduction, and the PoW version-gate / single-cost-floor state machine (prove no height admits two algorithms at one target post-activation).
- **Tooling to run:** KAT/Wycheproof-style vectors, differential/property fuzzing (cryptofuzz-style), constant-time analysis on the binary, and a 32/64-bit differential build test.

---

*Prepared from the internal adversarial pre-audit (2026-07-15); updated 2026-07-18 for the RC1-AUDIT-FREEZE anchor (`ad157eb`) — H2/H3/M3 landed, M5 added as section H with questions 9–13. Contains no secrets; defensive review of the owner's own authorized chain.*
