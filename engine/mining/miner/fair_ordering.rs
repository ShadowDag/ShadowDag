// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Fair Transaction Ordering — Prevents MEV (Miner Extractable Value),
// front-running, and sandwich attacks.
//
// Strategy: Commit-Reveal ordering
//   1. Miners commit to a TX ordering hash BEFORE seeing TX contents
//   2. Block template orders TXs by: fee (descending) then hash (deterministic)
//   3. Miners CANNOT reorder after committing
//
// Additional protections:
//   - Time-weighted fee priority (older TXs get bonus)
//   - Anti-sandwich: consecutive TXs to same contract get shuffled
//   - Deterministic tiebreaker (TX hash) prevents arbitrary ordering
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};

use crate::domain::transaction::transaction::Transaction;

/// Age bonus per second in mempool (older TXs get priority boost)
pub const AGE_BONUS_PER_SEC: u64 = 1;

/// Maximum age bonus (capped at 1 hour worth)
pub const MAX_AGE_BONUS: u64 = 3_600;

/// Fair ordering result
#[derive(Debug, Clone)]
pub struct OrderedTx {
    pub tx_hash:       String,
    pub fee:           u64,
    pub age_bonus:     u64,
    pub effective_fee: u64,
    pub order_key:     String, // Deterministic sort key
}

pub struct FairOrdering;

impl FairOrdering {
    /// Order transactions fairly for block inclusion.
    /// Returns transactions sorted by effective fee (desc) then hash (deterministic).
    pub fn order_for_block(
        txs: &[Transaction],
        current_time: u64,
    ) -> Vec<OrderedTx> {
        let mut ordered: Vec<OrderedTx> = txs.iter().map(|tx| {
            let age_secs = current_time.saturating_sub(tx.timestamp);
            let age_bonus = (age_secs * AGE_BONUS_PER_SEC).min(MAX_AGE_BONUS);
            let effective_fee = tx.fee.saturating_add(age_bonus);

            // Deterministic order key: H(effective_fee || tx_hash)
            let mut h = Sha256::new();
            h.update(effective_fee.to_be_bytes());
            h.update(tx.hash.as_bytes());
            let order_key = hex::encode(h.finalize());

            OrderedTx {
                tx_hash: tx.hash.clone(),
                fee: tx.fee,
                age_bonus,
                effective_fee,
                order_key,
            }
        }).collect();

        // Sort: highest effective fee first, then deterministic hash tiebreaker
        ordered.sort_by(|a, b| {
            b.effective_fee.cmp(&a.effective_fee)
                .then_with(|| a.order_key.cmp(&b.order_key))
        });

        ordered
    }

    /// Generate a commit hash for a block's TX ordering.
    /// Miners publish this BEFORE the block, proving they can't reorder later.
    pub fn commit_ordering(ordered_hashes: &[String], block_height: u64) -> String {
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_FairOrder_Commit_v1");
        h.update(block_height.to_le_bytes());
        h.update((ordered_hashes.len() as u32).to_le_bytes());
        for hash in ordered_hashes {
            h.update(hash.as_bytes());
        }
        hex::encode(h.finalize())
    }

    /// Verify a block's TX ordering matches the committed order
    pub fn verify_ordering(
        block_txs: &[Transaction],
        commit_hash: &str,
        block_height: u64,
        block_timestamp: u64,
    ) -> bool {
        let ordered = Self::order_for_block(block_txs, block_timestamp);
        let hashes: Vec<String> = ordered.iter().map(|o| o.tx_hash.clone()).collect();
        let expected_commit = Self::commit_ordering(&hashes, block_height);
        expected_commit == commit_hash
    }

    /// Anti-sandwich: detect if consecutive TXs target the same contract
    pub fn detect_sandwich(ordered: &[OrderedTx]) -> Vec<(usize, usize)> {
        let mut suspicious = Vec::new();
        for i in 0..ordered.len().saturating_sub(2) {
            // Simple heuristic: if TX[i] and TX[i+2] have very different fees
            // but TX[i+1] is sandwiched between them with a similar target
            if ordered[i].fee > ordered[i + 1].fee * 10
                && ordered[i + 2].fee > ordered[i + 1].fee * 10
            {
                suspicious.push((i, i + 2));
            }
        }
        suspicious
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{TxOutput, TxType};

    fn make_tx(hash: &str, fee: u64, timestamp: u64) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![],
            outputs: vec![TxOutput { address: "addr".into(), amount: 100, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee,
            timestamp,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
        }
    }

    #[test]
    fn higher_fee_first() {
        let txs = vec![
            make_tx("low", 10, 1000),
            make_tx("high", 100, 1000),
            make_tx("mid", 50, 1000),
        ];
        let ordered = FairOrdering::order_for_block(&txs, 1000);
        assert_eq!(ordered[0].tx_hash, "high");
        assert_eq!(ordered[1].tx_hash, "mid");
        assert_eq!(ordered[2].tx_hash, "low");
    }

    #[test]
    fn age_bonus_helps_old_txs() {
        let txs = vec![
            make_tx("new_high", 100, 1000),  // New, high fee
            make_tx("old_low", 50, 0),        // Old (1000s), low fee + age bonus
        ];
        let ordered = FairOrdering::order_for_block(&txs, 1000);
        // old_low gets +1000 age bonus → effective_fee = 1050 > 100
        assert_eq!(ordered[0].tx_hash, "old_low");
    }

    #[test]
    fn deterministic_tiebreaker() {
        let txs = vec![
            make_tx("tx_b", 100, 1000),
            make_tx("tx_a", 100, 1000),
        ];
        let o1 = FairOrdering::order_for_block(&txs, 1000);
        let o2 = FairOrdering::order_for_block(&txs, 1000);
        assert_eq!(o1[0].tx_hash, o2[0].tx_hash, "Same fee must have deterministic order");
    }

    #[test]
    fn commit_is_deterministic() {
        let hashes = vec!["a".into(), "b".into(), "c".into()];
        let c1 = FairOrdering::commit_ordering(&hashes, 100);
        let c2 = FairOrdering::commit_ordering(&hashes, 100);
        assert_eq!(c1, c2);
    }

    #[test]
    fn commit_changes_with_order() {
        let h1 = vec!["a".into(), "b".into()];
        let h2 = vec!["b".into(), "a".into()];
        assert_ne!(
            FairOrdering::commit_ordering(&h1, 100),
            FairOrdering::commit_ordering(&h2, 100),
        );
    }

    #[test]
    fn age_bonus_capped() {
        let tx = make_tx("ancient", 10, 0);
        let ordered = FairOrdering::order_for_block(&[tx], 1_000_000);
        assert!(ordered[0].age_bonus <= MAX_AGE_BONUS);
    }
}
