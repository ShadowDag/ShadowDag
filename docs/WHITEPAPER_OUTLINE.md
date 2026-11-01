# ShadowDAG — Whitepaper Outline

A skeleton for the project whitepaper, grounded in the implemented architecture.
Fill each section with prose, diagrams, and the team's economic decisions.
Sections marked **[DECIDE]** require choices not derivable from the code.

## 1. Introduction
- Problem: scalable + private money. Why a BlockDAG over a linear chain.
- One-paragraph summary of ShadowDAG (GHOSTDAG BlockDAG, privacy via RingCT,
  smart contracts via ShadowVM, ShadowHash PoW).
- Design goals and non-goals.

## 2. Consensus — GHOSTDAG
- BlockDAG model: blocks reference multiple parents; blue/red classification.
- Blue score, selected parent, virtual chain ordering.
- **Fork choice (heaviest cumulative work)** — tips ranked by total proof-of-work
  (`cumulative_work = Σ header.difficulty` along the selected-parent chain), then
  blue score, height, hash. (Implemented; see `full_node::cumulative_work`.)
- **Finality** — deep-reorg bound (`MAX_REORG_DEPTH`), enforced pre-write on both
  reorg directions. **[DECIDE]** dynamic finality / checkpoint policy.
- Parameters: K, max parents, target block time / BPS. **[DECIDE]** final values.

## 3. Proof of Work — ShadowHash
- Hash construction and domain separation (`shadow_hash_raw_full`).
- Difficulty representation and the retarget algorithm (EMA, DAG-width aware).
- ASIC-resistance stance. **[DECIDE]**

## 4. Privacy — RingCT
- Dual-key CLSAG ring signatures (sender ambiguity + linkability via key images).
- Pedersen commitments + range proofs (amount hiding).
- Stealth addresses + ECDH amount encoding (recipient privacy).
- Decoy selection policy and ring size. **[DECIDE]** default ring size.
- Transparent vs confidential transactions; the consensus gate.
- **Note:** cryptographic *soundness* must be validated by an external
  cryptographer (see `docs/AUDIT_SCOPE.md`).

## 5. Transactions & UTXO model
- UTXO set, transparent transfer format, signing
  (`SHADOW_TX_ID_V1` / `SHADOW_TX_SIGN_V1`, Ed25519).
- Fees and replay protection (chain-id binding, payload-hash anchor).
- Coinbase, reward split, maturity.

## 6. Smart contracts — ShadowVM
- Stack-based VM, U256 words, ~52 opcodes, gas metering.
- Execution model, reentrancy guard, state journaling/rollback.
- ShadowLang → ShadowASM → bytecode toolchain.
- State commitment. **[DECIDE]** whether contract state-root is consensus-committed
  (item "G" in the readiness doc — currently not in PoW).

## 7. Networking
- P2P protocol, peer discovery (seed nodes), gossip/relay.
- Dandelion transaction propagation (privacy).
- DoS protections (per-IP caps, bounded messages, orphan-pool bounds, ban scoring).

## 8. Economics / Tokenomics **[DECIDE — all of this]**
- Total supply / emission curve / halving schedule.
- Block reward + dev-fund split.
- Fee market and minimum fee.
- Initial distribution / premine (if any).

## 9. Wallets & ecosystem
- CLI, browser, and desktop wallets; HD derivation
  (`ShadowDAG/44'/999'/account'/change/index`), mnemonics, multisig, hardware.
- WASM/JS SDK for web wallets and dApps.
- Address format (`SD1`/`ST1`/`SR1` + 20-byte hash; subtype prefixes).

## 10. Storage & node architecture
- RocksDB layout; block store as source of truth; recovery model.
- **[DECIDE]** cross-store atomicity hardening (item "ST1").

## 11. Security
- Threat model, the hardening already performed, and the **mandatory external
  audit + public testnet** before mainnet.
- Disclosed limitations (multisig aggregation, HTTPS SDK, etc. — see readiness doc).
- **[DECIDE]** bug-bounty program, upgrade/governance process.

## 12. Roadmap
- Testnet → audit → mainnet → ecosystem (exchanges, explorers, more SDKs).

## Appendices
- A. RPC API (`docs/RPC_REFERENCE.md`).
- B. Node operator guide (`docs/NODE_OPERATOR_GUIDE.md`).
- C. Audit scope (`docs/AUDIT_SCOPE.md`).
- D. Consensus constants and genesis parameters.
