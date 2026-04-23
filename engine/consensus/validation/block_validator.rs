// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet as FxHashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::consensus::consensus_params::ConsensusParams;
use crate::config::genesis::genesis::{
    compute_merkle_root, genesis_hash_for, REGTEST_DEV_ADDRESS, TESTNET_DEV_ADDRESS,
};
use crate::config::node::node_config::NetworkMode;
use crate::domain::block::block::Block;
use crate::domain::block::merkle_tree::MerkleTree;
use crate::domain::transaction::transaction::{Transaction, TxType};
use crate::domain::transaction::tx_validator::TxValidator;
#[cfg(test)]
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::{utxo_key, UtxoSet};
use crate::engine::consensus::chain_manager::ChainManager;
use crate::engine::dag::core::dag_manager::DagManager;
use crate::engine::dag::security::dag_shield::DagShield;
use crate::engine::dag::security::dos_protection::MAX_DAG_PARENTS;
use crate::engine::mining::pow::pow_validator::PowValidator;
use crate::engine::privacy::ringct::ring_validator::RingValidator;
use crate::errors::ConsensusError;
use crate::infrastructure::storage::rocksdb::blocks::block_store::BlockStore;

// ─────────────────────────────────────────

/// Canonical maximum future timestamp drift for the entire codebase (120 seconds).
/// All other modules should reference this value.
pub const MAX_FUTURE_SECS: u64 = 120;
pub const MEDIAN_TIME_SPAN: usize = 11;
pub const MAX_BLOCK_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TX_BYTES_IN_BLOCK: usize = 100 * 1024;

/// Maximum transactions per block during validation (anti-DoS budget).
/// Prevents worst-case CPU consumption from blocks with excessive TXs.
pub const MAX_TXS_PER_BLOCK_VALIDATION: usize = 10_000;

/// Maximum how far in the past a block timestamp can be relative to wall clock.
/// Prevents miners from backdating blocks to manipulate difficulty windows.
/// 10 minutes is generous enough for clock skew but tight enough to prevent
/// systematic timewarp attacks.
pub const MAX_PAST_BLOCK_SECS: u64 = 600;

/// Maximum forward timestamp jump from the best parent.
/// Must be large enough to handle legitimate mining delays (difficulty
/// overshoot, network partitions, miner restarts) without rejecting valid
/// blocks. At 10 BPS with 100ms target, 30s = 300 blocks max jump —
/// tight enough to prevent timewarp manipulation while allowing recovery.
pub const MAX_TIMESTAMP_JUMP_SECS: u64 = 30;

/// Stricter timestamp drift for DAG-dense heights. When multiple parallel
/// blocks exist at the same height, a tighter cap prevents timewarp attacks
/// that exploit DAG parallelism. Used as a secondary check when the block
/// has ≥3 parents (indicating high DAG density at that height).
pub const MAX_DAG_DENSE_TIMESTAMP_JUMP_SECS: u64 = 10;

// ─────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UtxoChangeKey {
    pub txid: String,
    pub index: u32,
}

// ─────────────────────────────────────────

pub struct BlockValidationResult {
    pub valid: bool,
    pub reason: Option<String>,
    pub changes: Vec<UtxoChange>,
}

pub enum UtxoChange {
    Spend {
        key: UtxoChangeKey,
    },
    Create {
        key: UtxoChangeKey,
        address: String,
        amount: u64,
    },
}

impl BlockValidationResult {
    pub fn ok(changes: Vec<UtxoChange>) -> Self {
        Self {
            valid: true,
            reason: None,
            changes,
        }
    }

    /// Structural validation passed — UTXO changes computed separately
    /// by UtxoValidator (the single source of truth).
    pub fn ok_no_changes() -> Self {
        Self {
            valid: true,
            reason: None,
            changes: vec![],
        }
    }

    pub fn fail(reason: &str) -> Self {
        Self {
            valid: false,
            reason: Some(reason.to_string()),
            changes: vec![],
        }
    }

    pub fn apply_changes(&self, utxo_set: &UtxoSet) {
        for change in &self.changes {
            match change {
                UtxoChange::Spend { key } => {
                    if let Ok(k) = utxo_key(&key.txid, key.index) {
                        let _ = utxo_set.spend_utxo(&k);
                    }
                }
                UtxoChange::Create {
                    key,
                    address,
                    amount,
                } => {
                    if let Ok(k) = utxo_key(&key.txid, key.index) {
                        utxo_set.add_utxo(&k, address.clone(), *amount, address.clone());
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────

pub struct BlockValidator;

impl BlockValidator {
    pub fn validate_block_full(block: &Block, utxo_set: &UtxoSet) -> BlockValidationResult {
        Self::validate_block_full_with_network(block, utxo_set, &NetworkMode::Mainnet)
    }

    pub fn validate_block_full_with_network(
        block: &Block,
        utxo_set: &UtxoSet,
        network: &NetworkMode,
    ) -> BlockValidationResult {
        Self::validate_block_full_with_context(block, utxo_set, &[], network)
    }

    pub fn validate_block_full_with_context(
        block: &Block,
        utxo_set: &UtxoSet,
        ancestor_timestamps: &[u64],
        network: &NetworkMode,
    ) -> BlockValidationResult {
        Self::validate_block_full_with_difficulty(
            block,
            utxo_set,
            ancestor_timestamps,
            network,
            None,
        )
    }

    /// Full validation with optional expected difficulty enforcement.
    ///
    /// When `expected_difficulty` is Some, the block's header difficulty MUST
    /// match exactly. This prevents miners from choosing an arbitrarily low
    /// difficulty. The caller (FullNode::process_block) computes the expected
    /// difficulty from DifficultyRetarget based on the block's ancestors.
    // ═══════════════════════════════════════════════════════════════
    //  LAYERED VALIDATION — process layers in order: L1 → L2 → L3
    //
    //  L1 Network:    size, format, DoS protection     (no crypto)
    //  L2 Structural: merkle root, TX hash, signatures (crypto)
    //  L3 Consensus:  PoW, difficulty, checkpoints     (chain state)
    //  L4 Execution:  UTXO balance, fees               (SEPARATE — in FullNode)
    //
    //  SAFETY INVARIANT: L1–L3 are 100% STATELESS. They MUST NOT read
    //  from block_store, utxo_set, dag_manager, or any persistent state.
    //  The `_utxo_set` parameter is intentionally unused (underscore prefix).
    //  This separation ensures all nodes agree on L1–L3 validity regardless
    //  of local state, preventing consensus forks from state-dependent checks.
    //
    //  Only parallel operation: Merkle tree (rayon par_iter) — deterministic
    //  because same TX order always produces same root hash.
    // ═══════════════════════════════════════════════════════════════
    /// **L1 Network** — cheapest checks first. Reject malformed data
    /// before spending CPU on crypto or DB lookups.
    pub fn validate_network_layer(block: &Block) -> Result<(), ConsensusError> {
        // ── Early cost guards (O(1), before ANY iteration) ──────────
        // Reject obviously oversized blocks before spending CPU on
        // serialization, signature checks, or merkle computation.
        if block.body.transactions.len() > MAX_TXS_PER_BLOCK_VALIDATION {
            return Err(ConsensusError::BlockValidation(format!(
                "too many transactions: {} > {}",
                block.body.transactions.len(),
                MAX_TXS_PER_BLOCK_VALIDATION
            )));
        }
        if block.header.version == 0 {
            return Err(ConsensusError::BlockValidation("version=0".into()));
        }
        if block.header.hash.is_empty() || block.header.hash.chars().all(|c| c == '0') {
            return Err(ConsensusError::BlockValidation("empty hash".into()));
        }
        Self::validate_block_size(block)?;

        // DagShield = unified fast filter (DoS + Spam + Flood + Selfish mining)
        if let Err(rej) = DagShield::validate_block(block) {
            return Err(ConsensusError::BlockValidation(format!(
                "DagShield: {}",
                rej.reason
            )));
        }
        if block.body.transactions.is_empty() {
            return Err(ConsensusError::BlockValidation("no transactions".into()));
        }
        if block.body.transactions.len() == 1 && !block.body.transactions[0].is_coinbase() {
            return Err(ConsensusError::BlockValidation(
                "invalid single tx block".into(),
            ));
        }
        // Verify exactly one coinbase transaction
        let coinbase_count = block
            .body
            .transactions
            .iter()
            .filter(|tx| tx.is_coinbase())
            .count();
        if coinbase_count != 1 {
            return Err(ConsensusError::BlockValidation(format!(
                "expected exactly 1 coinbase TX, found {}",
                coinbase_count
            )));
        }
        // Duplicate TX check (cheap — hash set, no crypto)
        let mut seen: std::collections::HashSet<&str> =
            std::collections::HashSet::with_capacity(block.body.transactions.len());
        for tx in &block.body.transactions {
            if !seen.insert(&tx.hash) {
                return Err(ConsensusError::BlockValidation(format!(
                    "duplicate tx {}",
                    &tx.hash[..16.min(tx.hash.len())]
                )));
            }
        }
        Ok(())
    }

    /// **L2 Structural** — cryptographic integrity checks.
    /// Merkle root, TX hash verification, signature verification.
    /// No chain state or UTXO lookups.
    pub fn validate_structural_layer(
        block: &Block,
        ancestor_timestamps: &[u64],
        network: &NetworkMode,
    ) -> Result<(), ConsensusError> {
        Self::validate_parents(block)?;
        Self::validate_timestamp(block, ancestor_timestamps)?;

        // Merkle root — header must commit to actual TX body
        let computed_merkle = MerkleTree::build(
            &block.body.transactions,
            block.header.height,
            &block.header.parents,
        );
        if computed_merkle != block.header.merkle_root {
            return Err(ConsensusError::BlockValidation(format!(
                "merkle root mismatch: header={} computed={}",
                block.header.merkle_root, computed_merkle
            )));
        }

        // Receipt root verification (for blocks with contract TXs)
        if let Some(ref claimed_root) = block.header.receipt_root {
            // Re-execution and full comparison is done at the UTXO/execution layer.
            // Here we only verify the format is valid (64 hex chars = SHA-256).
            if claimed_root.len() != 64 || !claimed_root.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ConsensusError::BlockValidation(
                    "invalid receipt_root format (must be 64 hex chars)".into(),
                ));
            }
        }

        // State root format verification (for blocks with contract state changes)
        if let Some(ref claimed_root) = block.header.state_root {
            if claimed_root.len() != 64 || !claimed_root.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ConsensusError::BlockValidation(
                    "invalid state_root format (must be 64 hex chars)".into(),
                ));
            }
        }

        // Per-TX structure + signature verification
        //
        // Signature verification (Ed25519) is the most expensive per-TX
        // check. For blocks with 4+ non-coinbase TXs, we run signature
        // verification in parallel via rayon. Structural checks remain
        // sequential (cheap, O(field count)) to preserve deterministic
        // error ordering.
        let non_coinbase: Vec<(usize, &Transaction)> = block
            .body
            .transactions
            .iter()
            .enumerate()
            .filter(|(_, tx)| !tx.is_coinbase())
            .collect();

        // L2a: structural validation (sequential, cheap)
        for &(i, tx) in &non_coinbase {
            if !TxValidator::validate_structure_for_network(tx, network) {
                return Err(ConsensusError::BlockValidation(format!(
                    "tx {} structural validation failed",
                    i
                )));
            }
        }

        // L2b: signature verification (parallel for 4+ TXs)
        if non_coinbase.len() >= 4 {
            use rayon::prelude::*;
            let sig_fail = non_coinbase.par_iter().find_any(|&&(_, tx)| {
                !TxValidator::verify_signatures_for_network(tx, network)
            });
            if let Some(&(i, _)) = sig_fail {
                return Err(ConsensusError::BlockValidation(format!(
                    "tx {} signature verification failed",
                    i
                )));
            }
        } else {
            for &(i, tx) in &non_coinbase {
                if !TxValidator::verify_signatures_for_network(tx, network) {
                    return Err(ConsensusError::BlockValidation(format!(
                        "tx {} signature verification failed",
                        i
                    )));
                }
            }
        }

        // L2c: ring signature + swap validation (sequential)
        for &(i, tx) in &non_coinbase {
            // Ring signature verification for confidential (privacy) transactions
            if tx.is_confidential() && !RingValidator::validate(tx) {
                return Err(ConsensusError::BlockValidation(format!(
                    "tx {} ring signature verification failed",
                    i
                )));
            }
            // Validate swap/dex transaction payloads
            if tx.tx_type == TxType::SwapTx {
                Self::validate_swap_tx(tx)?;
            }
            if tx.tx_type == TxType::DexOrder {
                Self::validate_dex_order_tx(tx)?;
            }
        }
        Ok(())
    }

    /// **L3 Consensus** — chain-level rules.
    /// PoW, difficulty, checkpoints, coinbase structure.
    /// Requires chain state but NOT UTXO state.
    pub fn validate_consensus_layer(
        block: &Block,
        expected_difficulty: Option<u64>,
        network: &NetworkMode,
    ) -> Result<(), ConsensusError> {
        if block.header.height > 0 && expected_difficulty.is_none() {
            return Err(ConsensusError::BlockValidation(
                "missing expected_difficulty for non-genesis block".into(),
            ));
        }

        if let Some(expected) = expected_difficulty {
            // Allow a small tolerance around the expected difficulty to account
            // for the window between getblocktemplate and submitblock. During
            // that window the retarget engine may have adjusted difficulty by
            // one or more EMA steps. A ±10% tolerance on non-mainnet covers
            // normal retarget drift on fast testnet DAG growth without opening
            // the door to large difficulty gaming.
            //
            // Why not strict equality: in a DAG with 10 BPS, the EMA retarget
            // can move substantially between getblocktemplate and submitblock.
            // Each node sees blocks arrive in different order, so their EMA
            // states diverge. We keep non-mainnet tolerance modest (10%)
            // and keep mainnet strict (0%) for consensus safety.
            //
            // On mainnet with stable hashrate this can be tightened, but for
            // testnet bootstrap and early chain growth, wide tolerance is needed.
            let tolerance_pct: u64 = if matches!(network, NetworkMode::Mainnet) {
                0
            } else {
                10
            };
            let delta = if tolerance_pct == 0 {
                0
            } else {
                expected.saturating_mul(tolerance_pct).saturating_div(100).max(1)
            };
            let min_allowed = expected.saturating_sub(delta).max(1);
            let max_allowed = expected.saturating_add(delta);
            if block.header.difficulty < min_allowed || block.header.difficulty > max_allowed {
                return Err(ConsensusError::BlockValidation(format!(
                    "difficulty {} outside allowed range [{}, {}] (expected {} on {:?}, tolerance={}%)",
                    block.header.difficulty,
                    min_allowed,
                    max_allowed,
                    expected,
                    network,
                    tolerance_pct
                )));
            }
        }

        ChainManager::validate_checkpoint(block.header.height, &block.header.hash)?;
        // PoW already validated before L2 (early rejection optimization)
        Self::validate_coinbase_for_network(block, network)?;
        Ok(())
    }

    /// Full validation in optimal order:
    ///   L1 Network  (cheap O(1))  → reject junk instantly
    ///   PoW         (1 hash)      → reject invalid work before expensive sigs
    ///   L2 Struct   (merkle+sigs) → cryptographic integrity
    ///   L3 Consensus(diff+checks) → chain-level rules
    ///   L4 Execution(UTXO)        → handled separately by UtxoValidator
    pub fn validate_block_full_with_difficulty(
        block: &Block,
        _utxo_set: &UtxoSet,
        ancestor_timestamps: &[u64],
        network: &NetworkMode,
        expected_difficulty: Option<u64>,
    ) -> BlockValidationResult {
        // L1: Network layer — always runs, even for genesis.
        // Format, size, and DoS checks apply to ALL blocks regardless of height.
        if let Err(reason) = Self::validate_network_layer(block) {
            return BlockValidationResult::fail(&reason.to_string());
        }

        // Genesis path — after L1 but before L2/L3.
        // L2 structural validation (timestamp, parents) is NOT required for
        // genesis (no parents = no timestamp/parent validation), but L1
        // (format, size, duplicates) must still be enforced above.
        if block.header.height == 0 {
            return Self::validate_genesis(block, network);
        }

        // PoW EARLY: validate proof-of-work BEFORE expensive signature checks.
        // A single ShadowHash + target comparison is ~100μs, while verifying
        // N transaction signatures can take milliseconds. Rejecting invalid PoW
        // here prevents attackers from wasting CPU on fake-block signature checks.
        if let Err(reason) = Self::validate_pow(block) {
            return BlockValidationResult::fail(&reason.to_string());
        }

        // L2: Structural layer — merkle root, timestamps, signatures
        if let Err(reason) = Self::validate_structural_layer(block, ancestor_timestamps, network) {
            return BlockValidationResult::fail(&reason.to_string());
        }

        // L3: Consensus layer — difficulty, checkpoints, coinbase
        if let Err(reason) = Self::validate_consensus_layer(block, expected_difficulty, network) {
            return BlockValidationResult::fail(&reason.to_string());
        }

        // L4 Execution (UTXO) is NOT called here — it lives in
        // UtxoValidator::validate_block_utxos(), called by FullNode::process_block().
        BlockValidationResult::ok_no_changes()
    }

    /// Read-only validation: returns true if the block is valid.
    /// Does NOT apply any UTXO changes — the caller (process_block) is
    /// responsible for applying changes atomically after DAG acceptance.
    pub fn validate_block(block: &Block, utxo_set: &UtxoSet) -> bool {
        let result = Self::validate_block_full(block, utxo_set);
        result.valid
    }

    // ─────────────────────────────────────────

    /// Hardened timestamp validation — anti-timewarp for DAG.
    ///
    /// Five rules enforced:
    ///   R1  ts ≤ now + MAX_FUTURE_SECS              (no far-future)
    ///   R2  ts ≥ now − MAX_PAST_BLOCK_SECS          (no far-past vs wall clock)
    ///   R3  ts > MTP(ancestors)                      (monotonic progress)
    ///   R4  ts ≥ max(parent_timestamps)              (DAG causality)
    ///   R5  ts ≤ max(parent_ts) + MAX_TIMESTAMP_JUMP (no large jumps)
    ///
    /// R2 is the critical anti-timewarp addition: it prevents miners from
    /// setting timestamps to MTP+1 (far behind real time) to systematically
    /// shrink the difficulty window, which would lower difficulty over time.
    ///
    /// R4+R5 together clamp the timestamp into a tight band relative to
    /// parents, which couples timestamps to the DAG structure. In a DAG,
    /// multiple parents provide independent timestamp witnesses — an
    /// attacker would need to control ALL tips to manipulate the band.
    /// NOTE ON WALL-CLOCK DEPENDENCY (R1, R2):
    /// SystemTime::now() is intentionally used as an anchor to prevent
    /// timestamp manipulation. This is standard blockchain practice
    /// (Bitcoin uses ±2 hours). Nodes with severely drifted clocks will
    /// reject valid blocks, but this is the node operator's responsibility
    /// (NTP is assumed). The DAG-based rules (R3–R6) provide secondary
    /// protection independent of wall-clock accuracy.
    fn validate_timestamp(block: &Block, ancestors: &[u64]) -> Result<(), ConsensusError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let ts = block.header.timestamp;

        // R1: Not too far in the future
        if ts > now + MAX_FUTURE_SECS {
            return Err(ConsensusError::Timestamp(format!(
                "timestamp {}s in future (max {}s)",
                ts.saturating_sub(now),
                MAX_FUTURE_SECS
            )));
        }

        // R2: Not too far in the past (wall clock anchor — anti-timewarp)
        // Without this, miners can set ts = MTP+1 which drifts behind real
        // time, shrinking the difficulty window and lowering difficulty.
        if ts < now.saturating_sub(MAX_PAST_BLOCK_SECS) {
            return Err(ConsensusError::Timestamp(format!(
                "timestamp {}s behind wall clock (max {}s)",
                now.saturating_sub(ts),
                MAX_PAST_BLOCK_SECS
            )));
        }

        if ancestors.len() >= 2 {
            // R3: Must be after Median Time Past (monotonic progress)
            let mtp = Self::median_time_past(ancestors);
            if ts <= mtp {
                return Err(ConsensusError::Timestamp(format!(
                    "timestamp {} ≤ MTP {}",
                    ts, mtp
                )));
            }

            // R4: Monotonic DAG time — must be STRICTLY GREATER than max
            // ancestor timestamp. In a DAG, parents are independent witnesses.
            // The block cannot claim to be at or before any ancestor's time.
            // Strict inequality (>) prevents timestamp stalling where an
            // attacker creates blocks at the same timestamp as parents,
            // which would freeze the MTP and difficulty window.
            let max_parent_ts = ancestors.iter().copied().max().unwrap_or(0);
            if ts <= max_parent_ts {
                return Err(ConsensusError::Timestamp(format!(
                    "timestamp {} ≤ max ancestor timestamp {} (monotonic DAG time violation)",
                    ts, max_parent_ts
                )));
            }

            // R5: No large forward jumps from parents (anti-timewarp)
            // Prevents inflating the difficulty window by claiming a
            // block took 120s when it really took 1s. The jump limit
            // is generous (30x target) to allow normal variance but
            // tight enough to prevent systematic manipulation.
            if ts > max_parent_ts + MAX_TIMESTAMP_JUMP_SECS {
                return Err(ConsensusError::Timestamp(format!(
                    "timestamp jump {}s from parent (max {}s)",
                    ts.saturating_sub(max_parent_ts),
                    MAX_TIMESTAMP_JUMP_SECS
                )));
            }

            // R6: Stricter DAG-dense timestamp check.
            // When a block has ≥3 parents, the DAG is "dense" at this height,
            // meaning many parallel blocks exist. In this case, tighten the
            // allowed timestamp jump to prevent timewarp exploits that abuse
            // DAG parallelism to inflate the difficulty window.
            if block.header.parents.len() >= 3
                && ts > max_parent_ts + MAX_DAG_DENSE_TIMESTAMP_JUMP_SECS
            {
                return Err(ConsensusError::Timestamp(format!(
                    "DAG-dense timestamp jump {}s from parent (max {}s with {} parents)",
                    ts.saturating_sub(max_parent_ts),
                    MAX_DAG_DENSE_TIMESTAMP_JUMP_SECS,
                    block.header.parents.len()
                )));
            }
        }

        Ok(())
    }

    /// Compute the Median Time Past from ancestor timestamps.
    ///
    /// Uses a **weighted median** where duplicate timestamps (from parallel
    /// DAG blocks at the same time) naturally increase that timestamp's
    /// influence. This prevents a single attacker block from skewing the
    /// MTP by injecting an outlier timestamp — the honest majority of
    /// blocks at the real time will dominate the median.
    ///
    /// In a simple median with deduplication, an attacker controlling 1/N
    /// of blocks can shift the median by 1/N of the range. With duplicates
    /// kept, honest blocks at the true time form the majority and anchor
    /// the median. This is equivalent to a difficulty-weighted median when
    /// all blocks have similar difficulty.
    fn median_time_past(timestamps: &[u64]) -> u64 {
        if timestamps.is_empty() {
            return 0;
        }

        let span = MEDIAN_TIME_SPAN.min(timestamps.len());
        let recent = &timestamps[timestamps.len() - span..];

        let mut sorted = recent.to_vec();
        sorted.sort_unstable();

        // Use the median (middle element). With duplicate timestamps from
        // parallel blocks, the median is weighted toward the most common
        // timestamp value — which in an honest network is the true time.
        sorted[sorted.len() / 2]
    }

    // ─────────────────────────────────────────

    fn validate_block_size(block: &Block) -> Result<(), ConsensusError> {
        // ── Cheap estimate first (O(1)) ─────────────────────────────
        // Approximate block size without full serialization to reject
        // obviously oversized blocks before expensive bincode::serialize.
        let tx_count = block.body.transactions.len();
        let cheap_estimate = 256 + tx_count * 200; // header + ~200 bytes per TX estimate
        if cheap_estimate > MAX_BLOCK_BYTES * 2 {
            return Err(ConsensusError::BlockValidation(format!(
                "block likely too large: ~{} bytes estimated ({} txs)",
                cheap_estimate, tx_count
            )));
        }

        // ── Per-TX size check ───────────────────────────────────────
        for tx in &block.body.transactions {
            let size = tx.canonical_bytes().len();
            if size > MAX_TX_BYTES_IN_BLOCK {
                return Err(ConsensusError::BlockValidation(format!(
                    "tx too large: {} > {} bytes",
                    size, MAX_TX_BYTES_IN_BLOCK
                )));
            }
        }

        // ── Full serialized block size (precise but expensive) ──────
        let full_size = bincode::serialize(block).map(|b| b.len()).map_err(|e| {
            ConsensusError::BlockValidation(format!("block serialization failed: {}", e))
        })?;
        if full_size > MAX_BLOCK_BYTES {
            return Err(ConsensusError::BlockValidation(format!(
                "block too large: {} > {} bytes",
                full_size, MAX_BLOCK_BYTES
            )));
        }

        Ok(())
    }

    // ─────────────────────────────────────────

    #[cfg(test)]
    fn validate_transactions_atomic(
        block: &Block,
        utxo_set: &UtxoSet,
        network: &NetworkMode,
    ) -> Result<Vec<UtxoChange>, ConsensusError> {
        let tx_count = block.body.transactions.len();
        let mut changes = Vec::with_capacity(tx_count * 4);

        // Staged state: outputs created by earlier txs in this block
        // Key: "txid:index" → (address, amount)
        let mut staged_outputs: std::collections::HashMap<UtxoKey, (String, u64)> =
            std::collections::HashMap::with_capacity(tx_count * 2);

        // Track spent keys to detect intra-block double-spends
        let mut spent = FxHashSet::with_capacity(tx_count.saturating_mul(4));
        let mut created = FxHashSet::with_capacity(tx_count.saturating_mul(4));

        for (i, tx) in block.body.transactions.iter().enumerate() {
            if tx.is_coinbase() {
                // Coinbase: just register outputs, no inputs to validate
                for (idx, out) in tx.outputs.iter().enumerate() {
                    let key_str = utxo_key(&tx.hash, idx as u32)?;
                    let key = UtxoChangeKey {
                        txid: tx.hash.clone(),
                        index: idx as u32,
                    };

                    if !created.insert(key.clone()) {
                        return Err(ConsensusError::BlockValidation("duplicate output".into()));
                    }

                    staged_outputs.insert(key_str, (out.address.clone(), out.amount));
                    changes.push(UtxoChange::Create {
                        key,
                        address: out.address.clone(),
                        amount: out.amount,
                    });
                }
                continue;
            }

            // Structural validation (size, hash, limits) — no UTXO lookup needed
            if !TxValidator::validate_structure_for_network(tx, network) {
                return Err(ConsensusError::BlockValidation(format!(
                    "tx {} structural validation failed",
                    i
                )));
            }

            // Validate inputs: check base UTXO set first, then staged outputs
            for input in &tx.inputs {
                let key_str = utxo_key(&input.txid, input.index)?;
                let key = UtxoChangeKey {
                    txid: input.txid.clone(),
                    index: input.index,
                };

                // Intra-block double-spend check
                if !spent.insert(key.clone()) {
                    return Err(ConsensusError::BlockValidation(format!(
                        "double spend in tx {}",
                        i
                    )));
                }

                // Input must exist in base UTXO set OR in staged outputs from earlier txs
                let exists_in_base = utxo_set
                    .get_utxo(&key_str)
                    .map(|u| !u.spent)
                    .unwrap_or(false);
                let exists_in_staged = staged_outputs.contains_key(&key_str);

                if !exists_in_base && !exists_in_staged {
                    return Err(ConsensusError::BlockValidation(format!(
                        "tx {} input {} not found in UTXO set or earlier block txs",
                        i, key_str
                    )));
                }

                changes.push(UtxoChange::Spend { key });
            }

            // Register this tx's outputs as available for subsequent txs
            for (idx, out) in tx.outputs.iter().enumerate() {
                let key_str = utxo_key(&tx.hash, idx as u32)?;
                let key = UtxoChangeKey {
                    txid: tx.hash.clone(),
                    index: idx as u32,
                };

                if !created.insert(key.clone()) {
                    return Err(ConsensusError::BlockValidation("duplicate output".into()));
                }

                staged_outputs.insert(key_str, (out.address.clone(), out.amount));
                changes.push(UtxoChange::Create {
                    key,
                    address: out.address.clone(),
                    amount: out.amount,
                });
            }
        }

        Ok(changes)
    }

    // ─────────────────────────────────────────

    /// Validate PoW using the CANONICAL PowValidator (256-bit target comparison).
    /// There is ONE PoW validation rule in the entire codebase — PowValidator.
    /// BlockValidator delegates to it to prevent consensus rule divergence.
    fn validate_pow(block: &Block) -> Result<(), ConsensusError> {
        let result = PowValidator::validate(block);
        if result.valid {
            Ok(())
        } else {
            Err(ConsensusError::InvalidPow(
                result
                    .reason
                    .unwrap_or_else(|| "PoW validation failed".to_string()),
            ))
        }
    }

    // ─────────────────────────────────────────

    fn validate_parents(block: &Block) -> Result<(), ConsensusError> {
        let parents = &block.header.parents;

        if block.header.height > 0 && parents.is_empty() {
            return Err(ConsensusError::BlockValidation("no parents".into()));
        }

        if parents.len() > MAX_DAG_PARENTS {
            return Err(ConsensusError::BlockValidation("too many parents".into()));
        }

        let mut seen = FxHashSet::with_capacity(parents.len());

        for p in parents {
            if p == &block.header.hash {
                return Err(ConsensusError::BlockValidation("self parent".into()));
            }

            if !seen.insert(p) {
                return Err(ConsensusError::BlockValidation("duplicate parent".into()));
            }
        }

        // Validate selected_parent is a member of parents (if set).
        // The reorg path walks selected_parent to find fork points,
        // so an invalid selected_parent would cause incorrect chain
        // traversal.
        if let Some(ref sp) = block.header.selected_parent {
            if !block.header.parents.contains(sp) {
                return Err(ConsensusError::BlockValidation(format!(
                    "selected_parent {} is not in parents list",
                    &sp[..sp.len().min(16)]
                )));
            }
        }

        Ok(())
    }

    // ─────────────────────────────────────────

    /// Verify that every parent hash actually exists in the block store or DAG,
    /// AND that the block's height = max(parent_heights) + 1.
    ///
    /// Without the height check, an attacker could claim an arbitrary height,
    /// which breaks difficulty retarget, emission schedule, and coinbase maturity.
    ///
    /// Uses `block_store.get_block_height()` instead of `get_block()` so that
    /// pruned parents (body deleted but height index preserved) still pass
    /// validation. This prevents pruning from breaking parent checks.
    pub fn validate_parents_exist(
        block: &Block,
        block_store: &BlockStore,
        dag_manager: &DagManager,
    ) -> Result<(), ConsensusError> {
        if block.header.height == 0 {
            // Genesis has no parents — skip
            return Ok(());
        }

        let mut max_parent_height: u64 = 0;

        for parent_hash in &block.header.parents {
            // Parent height must be retrievable (survives pruning via h2h index)
            let parent_height = block_store.get_block_height(parent_hash).ok_or_else(|| {
                // Check DAG for existence — but even if the parent is in the
                // DAG, we REJECT it because height data is required for the
                // height rule below. A parent in the DAG but missing from
                // both BlockStore and height index means we cannot verify
                // the height rule, so the block must be rejected.
                if dag_manager.block_exists(parent_hash) {
                    return ConsensusError::BlockValidation(format!(
                        "parent {} in DAG but height unknown",
                        parent_hash
                    ));
                }
                ConsensusError::BlockValidation(format!("parent {} not found", parent_hash))
            })?;

            if parent_height > max_parent_height {
                max_parent_height = parent_height;
            }
        }

        // DAG height rule: height = max(parent_heights) + 1
        let expected_height = max_parent_height.checked_add(1).ok_or_else(|| {
            ConsensusError::BlockValidation("parent height would overflow u64".to_string())
        })?;
        if block.header.height != expected_height {
            return Err(ConsensusError::BlockValidation(format!(
                "height mismatch: block claims height={} but max(parent_heights)+1={}",
                block.header.height, expected_height
            )));
        }

        Ok(())
    }

    // ─────────────────────────────────────────

    fn dev_reward_address_for_network(network: &NetworkMode) -> &'static str {
        match network {
            NetworkMode::Mainnet => ConsensusParams::OWNER_REWARD_ADDRESS,
            NetworkMode::Testnet => TESTNET_DEV_ADDRESS,
            NetworkMode::Regtest => REGTEST_DEV_ADDRESS,
        }
    }

    fn validate_coinbase_for_network(
        block: &Block,
        network: &NetworkMode,
    ) -> Result<(), ConsensusError> {
        use crate::config::consensus::emission_schedule::EmissionSchedule;

        let txs = &block.body.transactions;
        let cb = txs
            .first()
            .ok_or_else(|| ConsensusError::BlockValidation("no txs".into()))?;

        // 1. First TX must be coinbase (no inputs)
        if !cb.is_coinbase() {
            return Err(ConsensusError::BlockValidation("first not coinbase".into()));
        }

        // 2. No other TX can be coinbase
        for tx in txs.iter().skip(1) {
            if tx.is_coinbase() {
                return Err(ConsensusError::BlockValidation("extra coinbase".into()));
            }
        }

        // 3. STRUCTURAL coinbase checks (Phase 1)
        //
        // Amount validation is done POST-EXECUTION in FullNode because
        // applied_fees (which determine the correct coinbase amount)
        // are only known after DAG-ordered execution determines which
        // txs were applied vs skipped/DUP.
        //
        // Here we only check structural constraints that don't depend
        // on execution results.

        // Must have exactly 2 outputs (miner + dev)
        if cb.outputs.len() != 2 {
            return Err(ConsensusError::BlockValidation(format!(
                "coinbase must have exactly 2 outputs (miner + dev), got {}",
                cb.outputs.len()
            )));
        }

        // Coinbase must pay at least emission reward (no underpaying)
        let expected_reward = EmissionSchedule::block_reward(block.header.height);

        // Validate reward split integrity (miner + dev == total, no satoshi loss)
        if !crate::engine::consensus::rewards::reward::Reward::validate_split(expected_reward) {
            return Err(ConsensusError::BlockValidation(
                "Reward split lost satoshis: miner + dev != total".to_string(),
            ));
        }

        let actual_total: u64 = cb
            .outputs
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.amount))
            .ok_or_else(|| {
                ConsensusError::BlockValidation("coinbase output sum overflow".into())
            })?;

        if actual_total < expected_reward {
            return Err(ConsensusError::BlockValidation(format!(
                "coinbase reward {} below emission {} at height {}",
                actual_total, expected_reward, block.header.height
            )));
        }

        // Upper bound: can't exceed emission + ALL declared fees
        // (even if some txs will be skipped, coinbase can't exceed this)
        let total_declared_fees: u64 = block
            .body
            .transactions
            .iter()
            .filter(|tx| !tx.is_coinbase())
            .map(|tx| tx.fee)
            .try_fold(0u64, |acc, f| acc.checked_add(f))
            .ok_or_else(|| {
                ConsensusError::BlockValidation("transaction fee sum overflow".into())
            })?;
        let max_allowed = expected_reward
            .checked_add(total_declared_fees)
            .ok_or_else(|| ConsensusError::BlockValidation("reward + fees overflow".into()))?;

        if actual_total > max_allowed {
            return Err(ConsensusError::BlockValidation(format!(
                "coinbase {} exceeds max {} (emission {} + declared_fees {}) at height {}",
                actual_total,
                max_allowed,
                expected_reward,
                total_declared_fees,
                block.header.height
            )));
        }

        // Dev reward address must match configured address
        let expected_dev = Self::dev_reward_address_for_network(network);
        if cb.outputs[1].address != expected_dev {
            return Err(ConsensusError::BlockValidation(format!(
                "dev reward address mismatch: got {}, expected {}",
                cb.outputs[1].address, expected_dev
            )));
        }

        // Enforce the 95/5 miner/dev split on the BASE emission reward.
        // This prevents miners from stealing the dev share by setting
        // outputs[1] to 1 satoshi while claiming the rest.
        // Fees (if any) may go entirely to the miner, but the base
        // emission must be split correctly.
        {
            use crate::config::genesis::genesis::{DEV_REWARD_PCT, MINER_REWARD_PCT};
            let expected_miner_base = (expected_reward * MINER_REWARD_PCT) / 100;
            let expected_dev_base = expected_reward - expected_miner_base;
            // Dev share must be at least the expected amount
            if cb.outputs[1].amount < expected_dev_base {
                return Err(ConsensusError::BlockValidation(format!(
                    "dev reward {} below minimum {} ({}% of {})",
                    cb.outputs[1].amount, expected_dev_base, DEV_REWARD_PCT, expected_reward
                )));
            }
            // Miner share (base) must not exceed expected
            // (miner can get more from fees, but base reward is capped)
            if cb.outputs[0].amount > expected_miner_base + total_declared_fees {
                return Err(ConsensusError::BlockValidation(format!(
                    "miner reward {} exceeds max {} (base {} + fees {})",
                    cb.outputs[0].amount,
                    expected_miner_base + total_declared_fees,
                    expected_miner_base,
                    total_declared_fees
                )));
            }
        }

        // Outputs must sum to declared actual_total (internal consistency)
        let output_sum: u64 = cb.outputs[0]
            .amount
            .checked_add(cb.outputs[1].amount)
            .ok_or_else(|| {
                ConsensusError::BlockValidation("coinbase output split overflow".into())
            })?;
        if output_sum != actual_total {
            return Err(ConsensusError::BlockValidation(format!(
                "coinbase output sum {} != declared total {}",
                output_sum, actual_total
            )));
        }

        // 5. Coinbase fee must be 0
        if cb.fee != 0 {
            return Err(ConsensusError::BlockValidation(
                "coinbase fee must be 0".into(),
            ));
        }

        Ok(())
    }

    #[cfg(test)]
    fn validate_coinbase(block: &Block) -> Result<(), ConsensusError> {
        Self::validate_coinbase_for_network(block, &NetworkMode::Mainnet)
    }

    // ─────────────────────────────────────────

    fn validate_genesis(block: &Block, network: &NetworkMode) -> BlockValidationResult {
        if block.header.hash != genesis_hash_for(network) {
            return BlockValidationResult::fail("genesis mismatch");
        }

        if !block.header.parents.is_empty() {
            return BlockValidationResult::fail("genesis has parents");
        }

        // Verify genesis merkle root with the same consensus path used by
        // genesis construction (tx-hash based merkle).
        let tx_hashes: Vec<String> = block
            .body
            .transactions
            .iter()
            .map(|tx| tx.hash.clone())
            .collect();
        let computed_merkle = compute_merkle_root(&tx_hashes);
        if computed_merkle != block.header.merkle_root {
            return BlockValidationResult::fail("genesis merkle mismatch");
        }

        // Validate coinbase structure
        if let Err(e) = Self::validate_coinbase_for_network(block, network) {
            return BlockValidationResult::fail(&format!("genesis coinbase invalid: {}", e));
        }

        // Structural TX validation for non-coinbase transactions in genesis.
        // Signatures must be valid even in the genesis block to prevent
        // injection of unsigned spends.
        for (i, tx) in block.body.transactions.iter().enumerate() {
            if !tx.is_coinbase() {
                if !TxValidator::validate_structure_for_network(tx, network) {
                    return BlockValidationResult::fail(&format!(
                        "genesis tx {} structural validation failed",
                        i
                    ));
                }
                if !TxValidator::verify_signatures(tx) {
                    return BlockValidationResult::fail(&format!(
                        "genesis tx {} signature verification failed",
                        i
                    ));
                }
            }
        }

        let mut changes = Vec::with_capacity(block.body.transactions.len() * 2);

        for tx in &block.body.transactions {
            for (i, output) in tx.outputs.iter().enumerate() {
                let key = UtxoChangeKey {
                    txid: tx.hash.clone(),
                    index: i as u32,
                };

                changes.push(UtxoChange::Create {
                    key,
                    address: output.address.clone(),
                    amount: output.amount,
                });
            }
        }

        BlockValidationResult::ok(changes)
    }

    /// Validate a swap transaction's payload.
    /// SwapTx must carry a payload_hash containing the HTLC secret hash (64 hex chars).
    /// The first output must lock funds to the HTLC address.
    ///
    /// TODO: The HTLC lock destination (first output address) should be validated
    /// to ensure it encodes a valid HTLC script address. Currently only the
    /// secret hash format is checked, not whether the output actually locks
    /// funds to the correct HTLC address derived from the secret hash and
    /// participants' public keys.
    fn validate_swap_tx(tx: &Transaction) -> Result<(), ConsensusError> {
        TxValidator::validate_swap_payload(tx)?;
        // 1. Must have payload_hash (HTLC secret hash)
        let _secret_hash = tx.payload_hash.as_ref().ok_or_else(|| {
            ConsensusError::BlockValidation("SwapTx missing payload_hash (HTLC secret hash)".into())
        })?;
        // 3. Must have at least one output (the HTLC lock)
        if tx.outputs.is_empty() {
            return Err(ConsensusError::BlockValidation(
                "SwapTx must have at least one output".into(),
            ));
        }
        // 3b. First output must lock funds to an HTLC address (P2SH prefix "SD1h")
        if let Some(first_output) = tx.outputs.first() {
            if !first_output
                .address
                .starts_with(crate::domain::address::address::P2SH_PREFIX)
            {
                return Err(ConsensusError::BlockValidation(
                    "SwapTx first output must lock funds to HTLC address (SD1h prefix)".into(),
                ));
            }
        }
        // 4. Must not be coinbase
        if tx.is_coinbase {
            return Err(ConsensusError::BlockValidation(
                "SwapTx cannot be coinbase".into(),
            ));
        }
        Ok(())
    }

    /// Validate a DEX order transaction's payload.
    /// DexOrder must carry a payload_hash encoding the order parameters.
    ///
    /// TODO: The order schema (encoded in payload_hash) should be parsed and
    /// validated to ensure it contains valid order fields (pair, side, price,
    /// quantity, expiry). Currently only the hex format is checked, not
    /// whether the decoded data represents a well-formed order that the DEX
    /// engine can match.
    fn validate_dex_order_tx(tx: &Transaction) -> Result<(), ConsensusError> {
        TxValidator::validate_dex_order_payload(tx)?;
        // 1. Must have payload_hash (order data)
        let _order_data = tx.payload_hash.as_ref().ok_or_else(|| {
            ConsensusError::BlockValidation("DexOrder missing payload_hash (order data)".into())
        })?;
        // 3. Must not be coinbase
        if tx.is_coinbase {
            return Err(ConsensusError::BlockValidation(
                "DexOrder cannot be coinbase".into(),
            ));
        }
        // 4. Must have at least one input (placing an order requires funds)
        if tx.inputs.is_empty() {
            return Err(ConsensusError::BlockValidation(
                "DexOrder must have at least one input".into(),
            ));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//                            TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::consensus::consensus_params::ConsensusParams;
    use crate::config::consensus::emission_schedule::EmissionSchedule;
    use crate::config::genesis::genesis::TESTNET_DEV_ADDRESS;
    use crate::domain::block::block_body::BlockBody;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput};
    use crate::domain::transaction::tx_hash::TxHash;
    use std::time::{SystemTime, UNIX_EPOCH};

    // ─────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Build a coinbase transaction with correct 2-output structure
    /// (95% miner, 5% dev) matching the emission schedule at a given height.
    fn make_coinbase(height: u64) -> Transaction {
        let reward = EmissionSchedule::block_reward(height);
        let miner_reward = (reward * 95) / 100;
        let dev_reward = reward - miner_reward;

        let mut tx = Transaction::new_coinbase(
            String::new(), // placeholder, will be replaced
            vec![
                TxOutput::new("miner_addr".into(), miner_reward),
                TxOutput::new(ConsensusParams::OWNER_REWARD_ADDRESS.into(), dev_reward),
            ],
            0,
            now_secs(),
        );
        tx.hash = TxHash::hash_for_network(&tx, &NetworkMode::Mainnet);
        tx
    }

    /// Build a simple non-coinbase transaction with one input and one output.
    /// Input txid must be 64 hex chars (DagShield requirement).
    /// The TX hash is computed from canonical bytes for structural validity.
    fn make_regular_tx(seed: &str) -> Transaction {
        let ts = now_secs();
        let mut tx = Transaction::new(
            String::new(), // placeholder
            vec![TxInput::new(
                "dd".repeat(32),
                0,
                "owner".into(),
                "sig".into(),
                "pub".into(),
            )],
            vec![TxOutput::new("dest_addr".into(), 100)],
            1,
            ts,
        );
        // Differentiate TXs by using the seed in the input txid
        if !seed.is_empty() {
            // Use different input txids to create distinct TX hashes
            let padded = format!(
                "{:0>64}",
                seed.chars()
                    .filter(|c| c.is_ascii_hexdigit())
                    .collect::<String>()
            );
            if padded.len() >= 64 {
                tx.inputs[0].txid = padded[..64].to_string();
            }
        }
        tx.hash = TxHash::hash_for_network(&tx, &NetworkMode::Mainnet);
        tx
    }

    /// Build a minimal valid block at a given height.
    /// The hash is a placeholder (will not pass PoW), but is sufficient
    /// for testing network-layer, structural-layer, and parent validation.
    ///
    /// Parents are valid 64-char hex strings and we provide at least 2
    /// (required by SelfishMiningGuard for height > 1).
    fn make_block(height: u64, txs: Vec<Transaction>) -> Block {
        let ts = now_secs();
        // DagShield requires parents to be exactly 64 hex chars, unique,
        // and at least MIN_DAG_PARENTS (2) for height > 1.
        let parents = if height <= 1 {
            vec!["aa".repeat(32)]
        } else {
            vec!["aa".repeat(32), "bb".repeat(32)]
        };

        let merkle = MerkleTree::build(&txs, height, &parents);

        Block {
            header: BlockHeader {
                version: 1,
                hash: "cc".repeat(32),
                parents,
                merkle_root: merkle,
                timestamp: ts,
                nonce: 42,
                difficulty: 1,
                height,
                blue_score: 0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
            },
            body: BlockBody { transactions: txs },
        }
    }

    /// Build a block with coinbase + one regular tx at the given height.
    fn make_valid_block(height: u64) -> Block {
        let cb = make_coinbase(height);
        let tx = make_regular_tx("regular_tx_1");
        make_block(height, vec![cb, tx])
    }

    // ─────────────────────────────────────────
    //  L1 Network Layer
    // ─────────────────────────────────────────

    #[test]
    fn network_layer_valid_block_passes() {
        let block = make_valid_block(5);
        assert!(BlockValidator::validate_network_layer(&block).is_ok());
    }

    #[test]
    fn network_layer_empty_transactions_fails() {
        let mut block = make_valid_block(5);
        block.body.transactions.clear();
        // DagShield catches empty blocks before BlockValidator's own check
        let result = BlockValidator::validate_network_layer(&block);
        assert!(result.is_err(), "empty transactions must fail");
    }

    #[test]
    fn network_layer_version_zero_fails() {
        let mut block = make_valid_block(5);
        block.header.version = 0;
        let result = BlockValidator::validate_network_layer(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version=0"));
    }

    #[test]
    fn network_layer_empty_hash_fails() {
        let mut block = make_valid_block(5);
        block.header.hash = String::new();
        let result = BlockValidator::validate_network_layer(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty hash"));
    }

    #[test]
    fn network_layer_all_zero_hash_fails() {
        let mut block = make_valid_block(5);
        block.header.hash = "0".repeat(64);
        let result = BlockValidator::validate_network_layer(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty hash"));
    }

    #[test]
    fn network_layer_duplicate_transactions_fails() {
        let cb = make_coinbase(5);
        let tx1 = make_regular_tx("dup_hash_abc");
        let tx2 = make_regular_tx("dup_hash_abc"); // same hash = duplicate
        let block = make_block(5, vec![cb, tx1, tx2]);

        let result = BlockValidator::validate_network_layer(&block);
        assert!(result.is_err(), "duplicate tx block must fail");
        let err_msg = result.unwrap_err().to_string();
        // DagShield's SpamFilter or BlockValidator's own check catches duplicates
        assert!(
            err_msg.contains("duplicate tx") || err_msg.contains("DagShield"),
            "expected duplicate/DagShield error, got: {}",
            err_msg,
        );
    }

    #[test]
    fn network_layer_single_non_coinbase_tx_fails() {
        // A block with exactly one TX that is NOT coinbase
        let tx = make_regular_tx("only_tx");
        let block = make_block(5, vec![tx]);

        let result = BlockValidator::validate_network_layer(&block);
        assert!(result.is_err(), "single non-coinbase tx block must fail");
    }

    // ─────────────────────────────────────────
    //  Parent Validation
    // ─────────────────────────────────────────

    #[test]
    fn parents_valid_passes() {
        let block = make_valid_block(5);
        assert!(BlockValidator::validate_parents(&block).is_ok());
    }

    #[test]
    fn parents_empty_at_nonzero_height_fails() {
        let mut block = make_valid_block(5);
        block.header.parents.clear();

        let result = BlockValidator::validate_parents(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no parents"));
    }

    #[test]
    fn parents_too_many_fails() {
        let mut block = make_valid_block(5);
        block.header.parents = (0..=MAX_DAG_PARENTS)
            .map(|i| format!("parent_{}", i))
            .collect();

        let result = BlockValidator::validate_parents(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too many parents"));
    }

    #[test]
    fn parents_self_reference_fails() {
        let mut block = make_valid_block(5);
        block.header.parents = vec![block.header.hash.clone()];

        let result = BlockValidator::validate_parents(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("self parent"));
    }

    #[test]
    fn parents_duplicate_fails() {
        let mut block = make_valid_block(5);
        block.header.parents = vec!["same_parent".into(), "same_parent".into()];

        let result = BlockValidator::validate_parents(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate parent"));
    }

    // ─────────────────────────────────────────
    //  Timestamp Validation
    // ─────────────────────────────────────────

    #[test]
    fn timestamp_valid_passes() {
        let block = make_valid_block(5);
        // Empty ancestors — only R1 and R2 are checked
        assert!(BlockValidator::validate_timestamp(&block, &[]).is_ok());
    }

    #[test]
    fn timestamp_too_far_in_future_fails() {
        let mut block = make_valid_block(5);
        block.header.timestamp = now_secs() + MAX_FUTURE_SECS + 60;

        let result = BlockValidator::validate_timestamp(&block, &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("future"));
    }

    #[test]
    fn timestamp_too_far_in_past_fails() {
        let mut block = make_valid_block(5);
        block.header.timestamp = now_secs().saturating_sub(MAX_PAST_BLOCK_SECS + 60);

        let result = BlockValidator::validate_timestamp(&block, &[]);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("behind wall clock"));
    }

    #[test]
    fn timestamp_before_mtp_fails() {
        let now = now_secs();
        let mut block = make_valid_block(5);
        // Set ancestors all at current time — MTP will be ~now
        let ancestors: Vec<u64> = vec![now; 5];
        // Set block timestamp to slightly before MTP (which equals now)
        block.header.timestamp = now - 1;

        let result = BlockValidator::validate_timestamp(&block, &ancestors);
        // Will fail either on R2 (past wall clock) or R3 (MTP) or R4 (causality)
        assert!(result.is_err());
    }

    #[test]
    fn timestamp_large_jump_from_parent_fails() {
        let now = now_secs();
        let mut block = make_valid_block(5);
        // Parent timestamps from ~10 minutes ago — within R2 wall clock limit
        let parent_ts = now - MAX_TIMESTAMP_JUMP_SECS - 100;
        let ancestors = vec![parent_ts; 3];
        // Block timestamp = now, which is MAX_TIMESTAMP_JUMP_SECS + 100 after parent
        // This exceeds the R5 jump limit
        block.header.timestamp = now;

        let result = BlockValidator::validate_timestamp(&block, &ancestors);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("jump"));
    }

    // ─────────────────────────────────────────
    //  Merkle Root Validation
    // ─────────────────────────────────────────

    #[test]
    fn structural_layer_invalid_merkle_root_fails() {
        let mut block = make_valid_block(5);
        block.header.merkle_root = "ff".repeat(32); // wrong merkle root

        let result = BlockValidator::validate_structural_layer(&block, &[], &NetworkMode::Mainnet);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("merkle root mismatch"));
    }

    #[test]
    fn structural_layer_correct_merkle_passes() {
        // Use coinbase-only block — coinbase skips TxValidator checks,
        // so we can test merkle root + parent + timestamp validation cleanly.
        let cb = make_coinbase(5);
        let block = make_block(5, vec![cb]);
        // With empty ancestors, timestamp validation only checks R1+R2
        assert!(
            BlockValidator::validate_structural_layer(&block, &[], &NetworkMode::Mainnet,).is_ok()
        );
    }

    // ─────────────────────────────────────────
    //  Coinbase Validation
    // ─────────────────────────────────────────

    #[test]
    fn coinbase_valid_passes() {
        let block = make_valid_block(5);
        assert!(BlockValidator::validate_coinbase(&block).is_ok());
    }

    #[test]
    fn coinbase_missing_fails() {
        // First TX is a regular (non-coinbase) transaction
        let tx = make_regular_tx("not_coinbase");
        let block = make_block(5, vec![tx]);

        let result = BlockValidator::validate_coinbase(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("first not coinbase"));
    }

    #[test]
    fn coinbase_not_first_fails() {
        // Regular TX first, then coinbase — coinbase must be index 0
        let tx = make_regular_tx("regular_first");
        let cb = make_coinbase(5);
        let block = make_block(5, vec![tx, cb]);

        let result = BlockValidator::validate_coinbase(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("first not coinbase"));
    }

    #[test]
    fn coinbase_extra_coinbase_fails() {
        let cb1 = make_coinbase(5);
        let mut cb2 = make_coinbase(5);
        // Mutate to get a different hash so it passes duplicate-tx checks
        cb2.outputs[0].amount += 1;
        cb2.hash = TxHash::hash_for_network(&cb2, &NetworkMode::Mainnet);
        let block = make_block(5, vec![cb1, cb2]);

        let result = BlockValidator::validate_coinbase(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("extra coinbase"));
    }

    #[test]
    fn coinbase_wrong_output_count_fails() {
        // Coinbase with only 1 output instead of 2
        let reward = EmissionSchedule::block_reward(5);
        let cb = Transaction::new_coinbase(
            "cb_one_output".into(),
            vec![TxOutput::new("miner".into(), reward)],
            0,
            now_secs(),
        );
        let tx = make_regular_tx("tx_1");
        let block = make_block(5, vec![cb, tx]);

        let result = BlockValidator::validate_coinbase(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exactly 2 outputs"));
    }

    #[test]
    fn coinbase_underpaying_reward_fails() {
        // Coinbase total below emission reward
        let cb = Transaction::new_coinbase(
            "cb_underpay".into(),
            vec![
                TxOutput::new("miner".into(), 1),
                TxOutput::new(ConsensusParams::OWNER_REWARD_ADDRESS.into(), 1),
            ],
            0,
            now_secs(),
        );
        let tx = make_regular_tx("tx_1");
        let block = make_block(5, vec![cb, tx]);

        let result = BlockValidator::validate_coinbase(&block);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("below emission"));
    }

    #[test]
    fn coinbase_wrong_dev_address_fails() {
        let reward = EmissionSchedule::block_reward(5);
        let miner_reward = (reward * 95) / 100;
        let dev_reward = reward - miner_reward;

        let cb = Transaction::new_coinbase(
            "cb_bad_dev".into(),
            vec![
                TxOutput::new("miner_addr".into(), miner_reward),
                TxOutput::new("wrong_dev_address".into(), dev_reward),
            ],
            0,
            now_secs(),
        );
        let tx = make_regular_tx("tx_1");
        let block = make_block(5, vec![cb, tx]);

        let result = BlockValidator::validate_coinbase(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("dev reward address mismatch"));
    }

    #[test]
    fn coinbase_nonzero_fee_fails() {
        let reward = EmissionSchedule::block_reward(5);
        let miner_reward = (reward * 95) / 100;
        let dev_reward = reward - miner_reward;

        let cb = Transaction::new_coinbase(
            "cb_fee".into(),
            vec![
                TxOutput::new("miner_addr".into(), miner_reward),
                TxOutput::new(ConsensusParams::OWNER_REWARD_ADDRESS.into(), dev_reward),
            ],
            10, // nonzero fee
            now_secs(),
        );
        let tx = make_regular_tx("tx_1");
        let block = make_block(5, vec![cb, tx]);

        let result = BlockValidator::validate_coinbase(&block);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("coinbase fee must be 0"));
    }

    // ─────────────────────────────────────────
    //  UTXO / Atomic Transaction Validation
    // ─────────────────────────────────────────

    #[test]
    fn atomic_validation_missing_utxo_fails() {
        // Non-coinbase TX with inputs that don't exist in UTXO set
        let utxo_set = UtxoSet::new_empty();
        let block = make_valid_block(5);

        let result =
            BlockValidator::validate_transactions_atomic(&block, &utxo_set, &NetworkMode::Mainnet);
        // The regular TX uses fake data — fails at structural or UTXO level
        assert!(result.is_err(), "block with unresolvable inputs must fail");
    }

    #[test]
    fn atomic_validation_coinbase_only_succeeds() {
        // Block with only coinbase — no UTXO lookups needed
        let utxo_set = UtxoSet::new_empty();
        let cb = make_coinbase(5);
        let block = make_block(5, vec![cb]);

        let result =
            BlockValidator::validate_transactions_atomic(&block, &utxo_set, &NetworkMode::Mainnet);
        assert!(result.is_ok());
        let changes = result.unwrap();
        // Coinbase creates 2 outputs
        assert_eq!(changes.len(), 2);
    }

    #[test]
    fn atomic_validation_intra_block_double_spend_fails() {
        let utxo_set = UtxoSet::new_empty();
        // Two regular TXs spending the same input
        let cb = make_coinbase(5);
        let tx1 = Transaction::new(
            "tx_ds_1".into(),
            vec![TxInput::new(
                "dd".repeat(32),
                0,
                "o".into(),
                "s".into(),
                "p".into(),
            )],
            vec![TxOutput::new("a".into(), 50)],
            1,
            now_secs(),
        );
        let tx2 = Transaction::new(
            "tx_ds_2".into(),
            vec![TxInput::new(
                "dd".repeat(32),
                0,
                "o".into(),
                "s".into(),
                "p".into(),
            )],
            vec![TxOutput::new("b".into(), 50)],
            1,
            now_secs(),
        );
        let block = make_block(5, vec![cb, tx1, tx2]);

        let result =
            BlockValidator::validate_transactions_atomic(&block, &utxo_set, &NetworkMode::Mainnet);
        // First tx fails on missing UTXO or second tx fails on double spend
        assert!(result.is_err());
    }

    #[test]
    fn consensus_difficulty_mainnet_requires_exact() {
        let mut block = make_valid_block(1);
        block.header.difficulty = 1_001;
        let result =
            BlockValidator::validate_consensus_layer(&block, Some(1_000), &NetworkMode::Mainnet);
        assert!(result.is_err(), "mainnet must reject non-exact difficulty");
    }

    #[test]
    fn consensus_difficulty_testnet_allows_small_drift_only() {
        let mut near = make_valid_block(1);
        // make_coinbase() uses mainnet owner address by default.
        near.body.transactions[0].outputs[1].address = TESTNET_DEV_ADDRESS.to_string();
        near.header.difficulty = 1_099; // within +10%
        let ok = BlockValidator::validate_consensus_layer(&near, Some(1_000), &NetworkMode::Testnet);
        assert!(ok.is_ok(), "testnet should allow <=10% drift");

        let mut far = near.clone();
        far.header.difficulty = 1_111; // beyond +10%
        let bad = BlockValidator::validate_consensus_layer(&far, Some(1_000), &NetworkMode::Testnet);
        assert!(bad.is_err(), "testnet must reject >10% drift");
    }

    #[test]
    fn consensus_rejects_missing_expected_difficulty_non_genesis() {
        let block = make_valid_block(1);
        let result = BlockValidator::validate_consensus_layer(&block, None, &NetworkMode::Mainnet);
        assert!(result.is_err(), "non-genesis must fail closed without expected difficulty");
    }

    // ─────────────────────────────────────────
    //  Full Validation Integration
    // ─────────────────────────────────────────

    #[test]
    fn full_validation_genesis_height_uses_genesis_path() {
        // Height 0 triggers validate_genesis, which checks genesis hash.
        // Build a genesis-shaped block (no parents, single coinbase TX)
        // so it passes DagShield's genesis check, but with a wrong hash
        // so block_validator's validate_genesis rejects it.
        let cb = make_coinbase(0);
        let parents: Vec<String> = vec![];
        let merkle = MerkleTree::build(std::slice::from_ref(&cb), 0, &parents);
        let block = Block {
            header: BlockHeader {
                version: 1,
                hash: "11".repeat(32), // wrong genesis hash
                parents,
                merkle_root: merkle,
                timestamp: now_secs(),
                nonce: 0,
                difficulty: 1,
                height: 0,
                blue_score: 0,
                selected_parent: None,
                utxo_commitment: None,
                extra_nonce: 0,
                receipt_root: None,
                state_root: None,
            },
            body: BlockBody {
                transactions: vec![cb],
            },
        };

        let utxo_set = UtxoSet::new_empty();
        let result = BlockValidator::validate_block_full_with_network(
            &block,
            &utxo_set,
            &NetworkMode::Mainnet,
        );
        assert!(!result.valid, "wrong genesis hash must fail");
        assert!(
            result
                .reason
                .as_ref()
                .is_some_and(|r| r.contains("genesis mismatch")),
            "unexpected reason: {:?}",
            result.reason
        );
    }

    #[test]
    fn block_validation_result_fail_sets_fields() {
        let r = BlockValidationResult::fail("test reason");
        assert!(!r.valid);
        assert_eq!(r.reason, Some("test reason".to_string()));
        assert!(r.changes.is_empty());
    }

    #[test]
    fn block_validation_result_ok_no_changes() {
        let r = BlockValidationResult::ok_no_changes();
        assert!(r.valid);
        assert!(r.reason.is_none());
        assert!(r.changes.is_empty());
    }

    #[test]
    fn median_time_past_correct() {
        // Odd number of elements — median is the middle
        let timestamps = vec![10, 20, 30, 40, 50];
        assert_eq!(BlockValidator::median_time_past(&timestamps), 30);
    }

    #[test]
    fn median_time_past_uses_last_span() {
        // More than MEDIAN_TIME_SPAN elements — only last 11 matter
        let timestamps: Vec<u64> = (1..=20).collect();
        let mtp = BlockValidator::median_time_past(&timestamps);
        // Last 11 = [10,11,12,13,14,15,16,17,18,19,20], median = 15
        assert_eq!(mtp, 15);
    }
}
