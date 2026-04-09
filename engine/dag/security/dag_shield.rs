// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::domain::block::block::Block;
use crate::domain::transaction::transaction::Transaction;
use crate::engine::dag::security::spam_filter::SpamFilter;
use crate::engine::dag::security::flood_protection::FloodProtection;
use crate::engine::dag::security::selfish_mining_guard::SelfishMiningGuard;
use crate::engine::dag::security::dos_protection::{
    DosProtection, MAX_DAG_PARENTS, MAX_TX_INPUTS, MAX_TX_OUTPUTS,
    MAX_OUTPUT_AMOUNT, MAX_FUTURE_TIMESTAMP_SECS, MIN_TX_SIZE_BYTES, MAX_TX_SIZE_BYTES,
};

/// Rejection reason with severity for ban scoring.
#[derive(Debug, Clone)]
pub struct ShieldRejection {
    pub reason: &'static str,
    /// Ban score to assign (0 = no ban, 10 = minor, 50+ = severe)
    pub ban_score: u32,
}

impl ShieldRejection {
    #[inline] fn minor(reason: &'static str) -> Self { Self { reason, ban_score: 10 } }
    #[inline] fn moderate(reason: &'static str) -> Self { Self { reason, ban_score: 25 } }
    #[inline] fn severe(reason: &'static str) -> Self { Self { reason, ban_score: 50 } }
}

pub struct DagShield;

impl DagShield {

    // ═══════════════════════════════════════════════════════════════
    //  BLOCK VALIDATION (full — used by block_validator L1)
    //
    //  Order: trivial O(1) → cheap O(n) → expensive (serialize)
    // ═══════════════════════════════════════════════════════════════
    pub fn validate(block: &Block) -> bool {
        Self::validate_block(block).is_ok()
    }

    /// Full block shield with rejection reason + ban severity.
    pub fn validate_block(block: &Block) -> Result<(), ShieldRejection> {

        // ─────────────────────────────────────────
        // 0. Genesis (special rules)
        // ─────────────────────────────────────────
        if block.header.height == 0 {
            return if Self::validate_genesis(block) { Ok(()) }
                   else { Err(ShieldRejection::severe("invalid genesis")) };
        }

        // ─────────────────────────────────────────
        // 1. Trivial O(1) checks (zero cost)
        // ─────────────────────────────────────────
        if block.body.transactions.is_empty() {
            return Err(ShieldRejection::moderate("empty block body"));
        }

        // Coinbase rules (first TX must be coinbase)
        if !Self::validate_coinbase(block) {
            return Err(ShieldRejection::moderate("invalid coinbase"));
        }

        // ─────────────────────────────────────────
        // 2. Cheap O(n) checks — hash set, no crypto
        // ─────────────────────────────────────────
        if !Self::detect_dag_anomaly(block) {
            return Err(ShieldRejection::severe("DAG anomaly (bad parents)"));
        }

        if !Self::detect_double_spend(block) {
            return Err(ShieldRejection::severe("double spend inside block"));
        }

        // ─────────────────────────────────────────
        // 3. Selfish mining (O(1) — parent count)
        // ─────────────────────────────────────────
        if !SelfishMiningGuard::validate(block) {
            return Err(ShieldRejection::moderate("selfish mining (too few parents)"));
        }

        // ─────────────────────────────────────────
        // 4. Flood protection (nonce + timestamp)
        // ─────────────────────────────────────────
        if !FloodProtection::validate(block) {
            return Err(ShieldRejection::minor("flood protection (nonce/timestamp)"));
        }

        // ─────────────────────────────────────────
        // 5. Spam filter (per-TX structural scan)
        // ─────────────────────────────────────────
        if !SpamFilter::validate(block) {
            return Err(ShieldRejection::moderate("spam filter (malformed TXs)"));
        }

        // ─────────────────────────────────────────
        // 6. DoS protection (includes serialization — LAST)
        // ─────────────────────────────────────────
        if !DosProtection::validate_block(block).is_ok() {
            return Err(ShieldRejection::severe("DoS protection (size/structural)"));
        }

        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════
    //  BLOCK PRE-VALIDATION (P2P layer — ultra-cheap, no serialize)
    //
    //  Used by P2P dispatch BEFORE queueing to reject obvious junk.
    //  Must be fast enough to run in the hot connection handler.
    // ═══════════════════════════════════════════════════════════════
    pub fn pre_validate_block(block: &Block) -> Result<(), ShieldRejection> {
        if block.header.hash.is_empty() {
            return Err(ShieldRejection::severe("empty block hash"));
        }
        if block.header.hash.len() != 64 {
            return Err(ShieldRejection::severe("invalid block hash length"));
        }
        if block.body.transactions.is_empty() && block.header.height > 0 {
            return Err(ShieldRejection::moderate("empty block body"));
        }
        if block.body.transactions.len() > 10_000 {
            return Err(ShieldRejection::severe("block TX count > 10K"));
        }
        let parents = &block.header.parents;
        if parents.is_empty() && block.header.height > 0 {
            return Err(ShieldRejection::severe("no parents (non-genesis)"));
        }
        if parents.len() > MAX_DAG_PARENTS {
            return Err(ShieldRejection::severe("too many parents"));
        }
        // Reject far-future/far-past timestamps (wall clock only, cheap)
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if block.header.timestamp > now + MAX_FUTURE_TIMESTAMP_SECS {
            return Err(ShieldRejection::minor("future timestamp"));
        }
        // NOTE: We intentionally do NOT reject old timestamps here.
        // During Initial Block Download (IBD), all historical blocks are
        // legitimately old. Timestamp validation for new blocks happens in
        // L2 (validate_structural_layer → validate_timestamp) which uses
        // MAX_PAST_BLOCK_SECS relative to parent timestamps, not wall clock.
        // The future-timestamp check above is safe because future blocks
        // are never valid regardless of sync mode.
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════
    //  TX VALIDATION (individual — used at P2P + mempool entry)
    //
    //  Order: trivial O(1) → cheap O(n) → NO crypto (that's L2)
    //  This is the "shield" filter: reject obvious junk before
    //  spending ANY CPU on signature verification or UTXO lookups.
    // ═══════════════════════════════════════════════════════════════

    /// Ultra-cheap TX pre-validation for P2P layer.
    /// Runs BEFORE queueing to PENDING_TXS. No crypto, no DB.
    pub fn pre_validate_tx(tx: &Transaction) -> Result<(), ShieldRejection> {
        // Hash format
        if tx.hash.is_empty() {
            return Err(ShieldRejection::severe("empty tx hash"));
        }
        if tx.hash.len() != 64 {
            return Err(ShieldRejection::moderate("invalid tx hash length"));
        }

        // Must have outputs
        if tx.outputs.is_empty() {
            return Err(ShieldRejection::moderate("no outputs"));
        }

        // Non-coinbase must have inputs
        if tx.inputs.is_empty() && !tx.is_coinbase {
            return Err(ShieldRejection::moderate("non-coinbase has no inputs"));
        }

        // Input/output count limits (cheap O(1))
        if tx.inputs.len() > MAX_TX_INPUTS {
            return Err(ShieldRejection::severe("too many inputs"));
        }
        if tx.outputs.len() > MAX_TX_OUTPUTS {
            return Err(ShieldRejection::severe("too many outputs"));
        }

        // Timestamp: reject far-future or ancient TXs
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if tx.timestamp > now + 120 {
            return Err(ShieldRejection::minor("future TX timestamp"));
        }
        // TX older than 24h is stale (MAX_TX_AGE_SECS from tx_validator)
        if tx.timestamp + 86_400 < now {
            return Err(ShieldRejection::minor("stale TX timestamp"));
        }

        // Output amount sanity (cheap O(n))
        let mut total: u128 = 0;
        for output in &tx.outputs {
            if output.amount == 0 {
                return Err(ShieldRejection::moderate("zero output amount"));
            }
            if output.amount > MAX_OUTPUT_AMOUNT {
                return Err(ShieldRejection::severe("output exceeds max"));
            }
            total = match total.checked_add(output.amount as u128) {
                Some(v) => v,
                None => return Err(ShieldRejection::severe("output overflow")),
            };
        }
        if total > u64::MAX as u128 {
            return Err(ShieldRejection::severe("total output overflow"));
        }

        // Duplicate input detection (cheap O(n) with hash set)
        if tx.inputs.len() > 1 {
            let mut seen = HashSet::with_capacity(tx.inputs.len());
            for input in &tx.inputs {
                if !seen.insert((&input.txid, input.index)) {
                    return Err(ShieldRejection::severe("duplicate inputs"));
                }
            }
        }

        // Coinbase structural: must have fee=0, no inputs
        if tx.is_coinbase && tx.fee != 0 {
            return Err(ShieldRejection::moderate("coinbase with non-zero fee"));
        }

        Ok(())
    }

    /// Full TX shield validation (mempool entry — includes size check).
    /// More expensive than pre_validate_tx because it serializes.
    pub fn validate_tx(tx: &Transaction) -> Result<(), ShieldRejection> {
        // Run cheap checks first
        Self::pre_validate_tx(tx)?;

        // Size check (requires serialization — expensive, so LAST)
        let size = match bincode::serialize(tx) {
            Ok(b) => b.len(),
            Err(_) => return Err(ShieldRejection::moderate("serialization failed")),
        };
        if size < MIN_TX_SIZE_BYTES {
            return Err(ShieldRejection::moderate("tx too small (spam)"));
        }
        if size > MAX_TX_SIZE_BYTES {
            return Err(ShieldRejection::severe("tx too large"));
        }

        Ok(())
    }

    // ─────────────────────────────────────────
    // Genesis validation (strict)
    // ─────────────────────────────────────────
    fn validate_genesis(block: &Block) -> bool {

        let txs = &block.body.transactions;

        if txs.len() != 1 {
            return false;
        }

        if !block.header.parents.is_empty() {
            return false;
        }

        let tx = &txs[0];

        // Coinbase must have no inputs
        if !tx.inputs.is_empty() {
            return false;
        }

        // Coinbase must have outputs
        if tx.outputs.is_empty() {
            return false;
        }

        true
    }

    // ─────────────────────────────────────────
    // Coinbase validation
    // ─────────────────────────────────────────
    fn validate_coinbase(block: &Block) -> bool {

        let txs = &block.body.transactions;

        if txs.is_empty() {
            return false;
        }

        let first = &txs[0];

        if !first.inputs.is_empty() {
            return false;
        }

        if first.outputs.is_empty() {
            return false;
        }

        let mut count = 0;

        for (i, tx) in txs.iter().enumerate() {

            // Reject empty junk tx
            if tx.inputs.is_empty() && tx.outputs.is_empty() {
                return false;
            }

            if tx.inputs.is_empty() {
                count += 1;

                if i != 0 {
                    return false;
                }

                if count > 1 {
                    return false;
                }
            }
        }

        count == 1
    }

    // ─────────────────────────────────────────
    // Double spend inside block
    // ─────────────────────────────────────────
    fn detect_double_spend(block: &Block) -> bool {

        let mut estimated_inputs = 0usize;

        for tx in &block.body.transactions {
            estimated_inputs = estimated_inputs.saturating_add(tx.inputs.len());
        }

        let mut seen_inputs: HashSet<(&str, u32)> =
            HashSet::with_capacity(estimated_inputs);

        for tx in &block.body.transactions {
            for input in &tx.inputs {

                if input.index > 10_000_000 || input.index == u32::MAX {
                    return false;
                }

                if input.txid.is_empty() {
                    return false;
                }

                let txid = input.txid.as_str();
                let bytes = txid.as_bytes();

                if bytes.len() != 64 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
                    return false;
                }

                if !seen_inputs.insert((txid, input.index)) {
                    return false;
                }
            }
        }

        true
    }

    // ─────────────────────────────────────────
    // DAG validation
    // ─────────────────────────────────────────
    fn detect_dag_anomaly(block: &Block) -> bool {

        let parents = &block.header.parents;

        if parents.is_empty() {
            return false;
        }

        if parents.len() > MAX_DAG_PARENTS {
            return false;
        }

        let mut unique: HashSet<&str> = HashSet::with_capacity(parents.len());

        for parent in parents {

            if parent.is_empty() {
                return false;
            }

            if parent == &block.header.hash {
                return false;
            }

            let p = parent.as_str();
            let bytes = p.as_bytes();

            if bytes.len() != 64 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
                return false;
            }

            if !unique.insert(p) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
    use crate::domain::block::block::Block;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::block::block_body::BlockBody;

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    }

    fn valid_hash() -> String {
        "a".repeat(64)
    }

    fn make_tx(hash: &str, fee: u64) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![TxInput {
                txid: valid_hash(),
                index: 0,
                owner: "alice".into(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput {
                address: "bob".into(),
                amount: 1000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee,
            timestamp: now_secs(),
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    fn make_coinbase(hash: &str) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "miner".into(),
                amount: 5000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 0,
            timestamp: now_secs(),
            is_coinbase: true,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    // ─────────────────────────────────────────
    // TX pre-validation tests
    // ─────────────────────────────────────────

    #[test]
    fn valid_tx_passes_pre_validate() {
        let tx = make_tx(&valid_hash(), 5);
        assert!(DagShield::pre_validate_tx(&tx).is_ok());
    }

    #[test]
    fn empty_hash_rejected() {
        let mut tx = make_tx(&valid_hash(), 5);
        tx.hash = String::new();
        let r = DagShield::pre_validate_tx(&tx);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().reason, "empty tx hash");
    }

    #[test]
    fn short_hash_rejected() {
        let mut tx = make_tx("abc123", 5);
        tx.hash = "abc123".into();
        let r = DagShield::pre_validate_tx(&tx);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().reason, "invalid tx hash length");
    }

    #[test]
    fn no_outputs_rejected() {
        let mut tx = make_tx(&valid_hash(), 5);
        tx.outputs.clear();
        assert!(DagShield::pre_validate_tx(&tx).is_err());
    }

    #[test]
    fn non_coinbase_no_inputs_rejected() {
        let mut tx = make_tx(&valid_hash(), 5);
        tx.inputs.clear();
        tx.is_coinbase = false;
        let r = DagShield::pre_validate_tx(&tx);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().reason, "non-coinbase has no inputs");
    }

    #[test]
    fn future_timestamp_rejected() {
        let mut tx = make_tx(&valid_hash(), 5);
        tx.timestamp = now_secs() + 300; // 5 min future
        assert!(DagShield::pre_validate_tx(&tx).is_err());
    }

    #[test]
    fn stale_timestamp_rejected() {
        let mut tx = make_tx(&valid_hash(), 5);
        tx.timestamp = 1000; // ancient
        assert!(DagShield::pre_validate_tx(&tx).is_err());
    }

    #[test]
    fn zero_output_amount_rejected() {
        let mut tx = make_tx(&valid_hash(), 5);
        tx.outputs[0].amount = 0;
        assert!(DagShield::pre_validate_tx(&tx).is_err());
    }

    #[test]
    fn duplicate_inputs_rejected() {
        let mut tx = make_tx(&valid_hash(), 5);
        let dup = tx.inputs[0].clone();
        tx.inputs.push(dup);
        assert!(DagShield::pre_validate_tx(&tx).is_err());
    }

    #[test]
    fn coinbase_with_fee_rejected() {
        let mut tx = make_coinbase(&valid_hash());
        tx.fee = 100;
        assert!(DagShield::pre_validate_tx(&tx).is_err());
    }

    #[test]
    fn valid_coinbase_passes() {
        let tx = make_coinbase(&valid_hash());
        assert!(DagShield::pre_validate_tx(&tx).is_ok());
    }

    // ─────────────────────────────────────────
    // Block pre-validation tests
    // ─────────────────────────────────────────

    fn make_block(height: u64, num_parents: usize) -> Block {
        let parents: Vec<String> = (0..num_parents)
            .map(|i| format!("{}{}", "b".repeat(63), format!("{:x}", i)))
            .collect();
        Block {
            header: BlockHeader::new_with_defaults(
                1,
                valid_hash(),
                parents,
                valid_hash(),
                now_secs(),
                42,
                1,
                height,
            ),
            body: BlockBody {
                transactions: vec![make_coinbase(&valid_hash())],
            },
        }
    }

    #[test]
    fn valid_block_passes_pre_validate() {
        let block = make_block(5, 3);
        assert!(DagShield::pre_validate_block(&block).is_ok());
    }

    #[test]
    fn block_empty_hash_rejected() {
        let mut block = make_block(5, 3);
        block.header.hash = String::new();
        assert!(DagShield::pre_validate_block(&block).is_err());
    }

    #[test]
    fn block_no_parents_rejected() {
        let mut block = make_block(5, 0);
        block.header.parents.clear();
        assert!(DagShield::pre_validate_block(&block).is_err());
    }

    #[test]
    fn block_future_timestamp_rejected() {
        let mut block = make_block(5, 3);
        block.header.timestamp = now_secs() + 1000;
        assert!(DagShield::pre_validate_block(&block).is_err());
    }

    #[test]
    fn block_empty_body_rejected() {
        let mut block = make_block(5, 3);
        block.body.transactions.clear();
        assert!(DagShield::pre_validate_block(&block).is_err());
    }

    // ─────────────────────────────────────────
    // ShieldRejection severity tests
    // ─────────────────────────────────────────

    #[test]
    fn severe_rejection_has_high_ban_score() {
        let r = ShieldRejection::severe("test");
        assert!(r.ban_score >= 50);
    }

    #[test]
    fn minor_rejection_has_low_ban_score() {
        let r = ShieldRejection::minor("test");
        assert!(r.ban_score <= 10);
    }
}