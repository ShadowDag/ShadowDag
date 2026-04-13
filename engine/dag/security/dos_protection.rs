// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::block::block::Block;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::utxo::utxo_set::utxo_key;

pub const MAX_BLOCK_SIZE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_BLOCK_TX_COUNT: usize = 5_000;

pub const MIN_TX_SIZE_BYTES: usize = 100;
pub const MAX_TX_SIZE_BYTES: usize = 100 * 1024;

pub const MAX_TX_INPUTS: usize = 50;
pub const MAX_TX_OUTPUTS: usize = 100;

pub const MAX_DAG_PARENTS: usize = crate::config::consensus::consensus_params::ConsensusParams::MAX_PARENTS;

pub const MAX_MEMPOOL_TX_COUNT: usize =
    crate::config::consensus::mempool_config::MempoolConfig::MAX_MEMPOOL_SIZE;
pub const MAX_MEMPOOL_SIZE_BYTES: usize =
    crate::config::consensus::mempool_config::MempoolConfig::MAX_MEMPOOL_BYTES;

pub const MIN_RELAY_FEE: u64 =
    crate::config::consensus::mempool_config::MempoolConfig::MIN_RELAY_FEE;
pub const MIN_FEE_PER_BYTE: u64 = 1;

pub const MAX_NONCE: u64 = u64::MAX;
pub const MAX_OUTPUT_AMOUNT: u64 = u64::MAX / 2;

/// Canonical value: 120s (see block_validator::MAX_FUTURE_SECS).
pub const MAX_FUTURE_TIMESTAMP_SECS: u64 = 120;
pub const MAX_PAST_TIMESTAMP_DRIFT: u64 = 600;

pub struct DosProtection;

impl DosProtection {

    // ─────────────────────────────────────────
    // BLOCK VALIDATION
    // ─────────────────────────────────────────
    pub fn validate_block(block: &Block) -> DosCheckResult {

        let txs = &block.body.transactions;

        if txs.is_empty() {
            return DosCheckResult::fail("Empty block".to_string());
        }

        if txs.len() > MAX_BLOCK_TX_COUNT {
            return DosCheckResult::fail("Too many transactions".to_string());
        }

        let mut seen_tx = HashSet::with_capacity(txs.len() * 2);
        let mut coinbase_count = 0;

        for (i, tx) in txs.iter().enumerate() {

            // 🔥 Validate tx داخليًا (مهم جدًا)
            if !Self::validate_transaction(tx).is_ok() {
                return DosCheckResult::fail("Invalid transaction inside block".to_string());
            }

            if tx.inputs.is_empty() {
                coinbase_count += 1;

                if i != 0 {
                    return DosCheckResult::fail("Coinbase must be first".to_string());
                }
            }

            if !seen_tx.insert(&tx.hash) {
                return DosCheckResult::fail("Duplicate tx".to_string());
            }
        }

        if coinbase_count != 1 {
            return DosCheckResult::fail("Invalid coinbase count".to_string());
        }

        // DAG
        let parents = &block.header.parents;

        // Genesis is the only block with no parents by design.
        if parents.is_empty() && block.header.height > 0 {
            return DosCheckResult::fail("No parents".to_string());
        }

        if parents.len() > MAX_DAG_PARENTS {
            return DosCheckResult::fail("Too many parents".to_string());
        }

        let mut seen = HashSet::with_capacity(parents.len() * 2);
        for parent in parents {
            if !seen.insert(parent) {
                return DosCheckResult::fail("Duplicate parent".to_string());
            }
        }

        // Nonce — only reject the MAX_NONCE sentinel value.
        // nonce==0 is rare but valid: a miner can solve PoW on the first try.
        if block.header.nonce == MAX_NONCE {
            return DosCheckResult::fail("Invalid nonce (MAX_NONCE sentinel)".to_string());
        }

        // Timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let future_limit = now.saturating_add(MAX_FUTURE_TIMESTAMP_SECS);
        let past_limit = now.saturating_sub(MAX_PAST_TIMESTAMP_DRIFT);

        if block.header.timestamp > future_limit {
            return DosCheckResult::fail("Future timestamp".to_string());
        }

        if block.header.timestamp < past_limit {
            return DosCheckResult::fail("Old timestamp".to_string());
        }

        // Size (آخر خطوة)
        let bytes = match bincode::serialize(block) {
            Ok(b) => b,
            Err(_) => return DosCheckResult::fail("Serialization fail".to_string())
        };

        if bytes.len() > MAX_BLOCK_SIZE_BYTES {
            return DosCheckResult::fail("Block too large".to_string());
        }

        DosCheckResult::pass()
    }

    // ─────────────────────────────────────────
    // TRANSACTION VALIDATION
    // ─────────────────────────────────────────
    pub fn validate_transaction(tx: &Transaction) -> DosCheckResult {

        if tx.outputs.is_empty() {
            return DosCheckResult::fail("No outputs".to_string());
        }

        let is_coinbase = tx.inputs.is_empty();

        // Serialize
        let bytes = match bincode::serialize(tx) {
            Ok(b) => b,
            Err(_) => return DosCheckResult::fail("Serialization fail".to_string())
        };

        let size = bytes.len();

        if size == 0 {
            return DosCheckResult::fail("Invalid size".to_string());
        }

        if size < MIN_TX_SIZE_BYTES {
            return DosCheckResult::fail("Tx too small (spam)".to_string());
        }

        if size > MAX_TX_SIZE_BYTES {
            return DosCheckResult::fail("Tx too large".to_string());
        }

        // Limits
        if tx.inputs.len() > MAX_TX_INPUTS {
            return DosCheckResult::fail("Too many inputs".to_string());
        }

        if tx.outputs.len() > MAX_TX_OUTPUTS {
            return DosCheckResult::fail("Too many outputs".to_string());
        }

        // Duplicate inputs
        let mut seen_inputs = HashSet::with_capacity(tx.inputs.len() * 2);
        for input in &tx.inputs {
            match utxo_key(&input.txid, input.index) {
                Ok(k) => {
                    if !seen_inputs.insert(k) {
                        return DosCheckResult::fail("Duplicate inputs".to_string());
                    }
                }
                Err(_) => return DosCheckResult::fail("Invalid input key".to_string()),
            }
        }

        // Outputs
        let mut total: u128 = 0;

        for output in &tx.outputs {

            if output.amount == 0 {
                return DosCheckResult::fail("Zero output".to_string());
            }

            if output.amount > MAX_OUTPUT_AMOUNT {
                return DosCheckResult::fail("Output too large".to_string());
            }

            // Note: Same address+amount combinations ARE valid (e.g., two payments
            // of 1000 to the same address). We only check for structural issues,
            // not duplicate (address, amount) pairs.

            total = match total.checked_add(output.amount as u128) {
                Some(v) => v,
                None => return DosCheckResult::fail("Overflow".to_string())
            };
        }

        if total > u64::MAX as u128 {
            return DosCheckResult::fail("Total overflow".to_string());
        }

        // Coinbase
        // Coinbase structural check only (fee validation is L4 Execution)
        if is_coinbase
            && tx.fee != 0 {
                return DosCheckResult::fail("Coinbase fee must be zero".to_string());
            }

        // NOTE: Fee amount, fee-per-byte, and fee-vs-total checks belong in
        // the Execution layer (L4), not in DoS protection (L1).
        // DoS protection should only reject obviously malformed data,
        // not enforce economic policy.

        DosCheckResult::pass()
    }
}

// ─────────────────────────────────────────
#[derive(Debug)]
pub struct DosCheckResult {
    pub passed: bool,
    pub reason: Option<String>,
}

impl DosCheckResult {
    pub fn pass() -> Self {
        Self { passed: true, reason: None }
    }

    pub fn fail(reason: String) -> Self {
        Self { passed: false, reason: Some(reason) }
    }

    pub fn is_ok(&self) -> bool {
        self.passed
    }
}
