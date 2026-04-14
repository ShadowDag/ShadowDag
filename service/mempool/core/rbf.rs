// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// RBF (Replace-By-Fee) — Allow transactions to be replaced by higher-fee
// versions. This prevents stuck transactions and enables fee bumping.
//
// Rules (stricter than Bitcoin BIP-125):
//   1. Replacement must pay HIGHER fee (not just higher fee rate)
//   2. Replacement must pay at least MIN_FEE_BUMP more than original
//   3. Replacement must not add new unconfirmed inputs
//   4. Maximum replacement chain depth = 25
//   5. Total replacement cost must cover evicted transaction fees
//
// DAG-specific considerations:
//   - In a DAG, the same TX might appear in multiple block candidates
//   - RBF replacement must propagate to all pending block templates
//   - Short block times (1s) make RBF less critical but still useful
// ═══════════════════════════════════════════════════════════════════════════

use crate::config::consensus::mempool_config::MempoolConfig;
use crate::domain::transaction::transaction::Transaction;

pub const MIN_FEE_BUMP: u64 = MempoolConfig::MIN_FEE_BUMP;
pub const MAX_REPLACEMENT_DEPTH: usize = MempoolConfig::MAX_REPLACEMENT_DEPTH;
pub const MAX_EVICTIONS: usize = MempoolConfig::MAX_RBF_EVICTIONS;

/// RBF evaluation result
#[derive(Debug, Clone)]
pub enum RbfResult {
    /// Replacement accepted — returns list of evicted TX hashes
    Accepted { evicted: Vec<String> },
    /// Fee too low
    FeeTooLow { required: u64, provided: u64 },
    /// No conflict (not a replacement, regular TX)
    NoConflict,
    /// Replacement would evict too many transactions
    TooManyEvictions { count: usize },
    /// Replacement chain too deep
    ChainTooDeep { depth: usize },
    /// Replacement introduces new unconfirmed inputs
    NewUnconfirmedInputs,
    /// Replacement rejected due to malformed data
    Rejected { reason: String },
}

/// Information about a mempool transaction for RBF evaluation
#[derive(Debug, Clone)]
pub struct MempoolTxInfo {
    pub hash: String,
    pub fee: u64,
    pub fee_rate: f64, // fee per byte
    pub size: usize,
    /// Input keys this TX spends
    pub inputs: Vec<String>,
    /// Other TX hashes that depend on this TX's outputs
    pub dependents: Vec<String>,
    /// How many replacements have been applied to this TX chain
    pub replacement_depth: usize,
}

pub struct RbfEngine;

impl RbfEngine {
    /// Evaluate whether a new transaction should replace existing ones.
    ///
    /// `new_tx`: The incoming transaction
    /// `conflicting`: Existing mempool TXs that spend the same inputs
    /// `confirmed_utxo_keys`: Set of UTXO keys known to be confirmed on-chain
    pub fn evaluate(
        new_tx: &Transaction,
        conflicting: &[MempoolTxInfo],
        confirmed_utxo_keys: &std::collections::HashSet<String>,
    ) -> RbfResult {
        // No conflicts = not a replacement
        if conflicting.is_empty() {
            return RbfResult::NoConflict;
        }

        // Rule 1: Calculate total fee of all conflicting TXs AND their dependents.
        // BUG FIX: Previously only summed direct conflict fees, but dependents
        // are also evicted (see evicted list below). The replacement must cover
        // ALL evicted fees to prevent net fee reduction in the mempool.
        //
        // NOTE: Dependent fees are approximated from the MempoolTxInfo passed
        // by the caller. For full accuracy the caller should populate
        // `dependent_fees` or the engine should look up each dependent.
        // As a pragmatic fix, we sum each conflict's fee plus a per-dependent
        // estimate of MIN_FEE_BUMP (the minimum any valid TX must pay).
        let total_evicted_fee: u64 = match conflicting.iter().try_fold(0u64, |acc, tx| {
            // Sum the conflict's own fee
            let with_own = acc.checked_add(tx.fee)?;
            // Sum estimated fees for dependents that will also be evicted.
            // Each dependent is a valid mempool TX, so it paid at least
            // MIN_FEE_BUMP. This is a lower bound; the actual fee may be higher.
            let dep_fees = (tx.dependents.len() as u64).checked_mul(MIN_FEE_BUMP)?;
            with_own.checked_add(dep_fees)
        }) {
            Some(total) => total,
            None => {
                return RbfResult::Rejected {
                    reason: "evicted fee total overflows u64".to_string(),
                }
            }
        };

        let total_eviction_count: usize = conflicting
            .iter()
            .map(|tx| 1 + tx.dependents.len())
            .fold(0usize, |acc, n| acc.saturating_add(n));

        // Rule 2: New TX must pay more than all evicted TXs combined + minimum bump
        let required_fee = total_evicted_fee.saturating_add(MIN_FEE_BUMP);
        if new_tx.fee < required_fee {
            return RbfResult::FeeTooLow {
                required: required_fee,
                provided: new_tx.fee,
            };
        }

        // Rule 3: Check replacement chain depth
        let max_depth = conflicting
            .iter()
            .map(|tx| tx.replacement_depth)
            .max()
            .unwrap_or(0);
        if max_depth + 1 > MAX_REPLACEMENT_DEPTH {
            return RbfResult::ChainTooDeep {
                depth: max_depth + 1,
            };
        }

        // Rule 4: Check total evictions
        if total_eviction_count > MAX_EVICTIONS {
            return RbfResult::TooManyEvictions {
                count: total_eviction_count,
            };
        }

        // Rule 5: New TX must not introduce new unconfirmed inputs
        // (all inputs must be either confirmed UTXOs or same as original)
        let original_inputs: std::collections::HashSet<String> = conflicting
            .iter()
            .flat_map(|tx| tx.inputs.iter().cloned())
            .collect();

        for input in &new_tx.inputs {
            let k = match crate::domain::utxo::utxo_set::utxo_key(&input.txid, input.index) {
                Ok(k) => k,
                Err(_) => {
                    return RbfResult::Rejected {
                        reason: format!(
                            "input txid '{}' is malformed (must be 64-char hex)",
                            input.txid
                        ),
                    }
                }
            };
            let key = k.to_string();
            if !original_inputs.contains(&key) && !confirmed_utxo_keys.contains(&key) {
                return RbfResult::NewUnconfirmedInputs;
            }
        }

        // All rules pass — accept replacement.
        // BUG FIX: Deduplicate the eviction list. A dependent TX may appear
        // in multiple conflict entries (e.g., a child spending outputs from
        // two conflicting parents). Without dedup, remove_transaction is
        // called twice for the same hash, wasting work and producing
        // confusing telemetry.
        let mut seen = std::collections::HashSet::new();
        let evicted: Vec<String> = conflicting
            .iter()
            .flat_map(|tx| {
                let mut hashes = vec![tx.hash.clone()];
                hashes.extend(tx.dependents.clone());
                hashes
            })
            .filter(|h| seen.insert(h.clone()))
            .collect();

        RbfResult::Accepted { evicted }
    }

    /// Calculate the minimum fee needed to replace a set of transactions.
    /// Includes estimated descendant fees (consistent with evaluate()).
    pub fn minimum_replacement_fee(conflicting: &[MempoolTxInfo]) -> u64 {
        let total: u64 = conflicting
            .iter()
            .try_fold(0u64, |acc, tx| {
                let with_own = acc.checked_add(tx.fee)?;
                let dep_fees = (tx.dependents.len() as u64).checked_mul(MIN_FEE_BUMP)?;
                with_own.checked_add(dep_fees)
            })
            .unwrap_or(u64::MAX);
        total.saturating_add(MIN_FEE_BUMP)
    }

    /// Check if a transaction signals RBF (opt-in)
    /// In ShadowDAG, all transactions are RBF-eligible by default.
    pub fn is_rbf_eligible(_tx: &Transaction) -> bool {
        true // All TXs are replaceable in ShadowDAG
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{TxInput, TxOutput, TxType};

    /// Convert a short test name to a deterministic 64-char hex hash.
    fn th(name: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(name.as_bytes()))
    }

    fn make_tx(hash: &str, fee: u64) -> Transaction {
        Transaction {
            hash: th(hash),
            inputs: vec![TxInput::new(
                th("prev"),
                0,
                "owner".into(),
                "sig".into(),
                "pk".into(),
            )],
            outputs: vec![TxOutput {
                address: "dest".into(),
                amount: 1000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee,
            timestamp: 1000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    /// Build a HashSet of confirmed UTXO keys for test transactions.
    /// Includes the standard "prev:0" key used by make_tx / make_mempool_tx.
    fn confirmed_keys() -> std::collections::HashSet<String> {
        let key = crate::domain::utxo::utxo_set::utxo_key(&th("prev"), 0)
            .expect("test hash must be valid")
            .to_string();
        std::collections::HashSet::from([key])
    }

    fn make_mempool_tx(hash: &str, fee: u64) -> MempoolTxInfo {
        let prev_key = crate::domain::utxo::utxo_set::utxo_key(&th("prev"), 0)
            .expect("test hash must be valid")
            .to_string();
        MempoolTxInfo {
            hash: th(hash),
            fee,
            fee_rate: fee as f64 / 200.0,
            size: 200,
            inputs: vec![prev_key],
            dependents: vec![],
            replacement_depth: 0,
        }
    }

    #[test]
    fn no_conflict_passes_through() {
        let tx = make_tx("new", 5000);
        let result = RbfEngine::evaluate(&tx, &[], &confirmed_keys());
        assert!(matches!(result, RbfResult::NoConflict));
    }

    #[test]
    fn higher_fee_replaces() {
        let tx = make_tx("new", 10_000);
        let existing = vec![make_mempool_tx("old", 5_000)];
        let result = RbfEngine::evaluate(&tx, &existing, &confirmed_keys());
        match result {
            RbfResult::Accepted { evicted } => {
                assert!(evicted.contains(&th("old")));
            }
            _ => panic!("Should accept higher-fee replacement"),
        }
    }

    #[test]
    fn lower_fee_rejected() {
        let tx = make_tx("new", 100);
        let existing = vec![make_mempool_tx("old", 5_000)];
        let result = RbfEngine::evaluate(&tx, &existing, &confirmed_keys());
        assert!(matches!(result, RbfResult::FeeTooLow { .. }));
    }

    #[test]
    fn must_cover_all_evicted_fees() {
        let tx = make_tx("new", 6_000);
        let existing = vec![
            make_mempool_tx("old1", 3_000),
            make_mempool_tx("old2", 3_000),
        ];
        // Needs 3000 + 3000 + 1000 (bump) = 7000, but only has 6000
        let result = RbfEngine::evaluate(&tx, &existing, &confirmed_keys());
        assert!(matches!(result, RbfResult::FeeTooLow { .. }));
    }

    #[test]
    fn covers_all_evicted_plus_bump() {
        let tx = make_tx("new", 8_000);
        let existing = vec![
            make_mempool_tx("old1", 3_000),
            make_mempool_tx("old2", 3_000),
        ];
        // 3000 + 3000 + 1000 = 7000 < 8000 → accepted
        let result = RbfEngine::evaluate(&tx, &existing, &confirmed_keys());
        assert!(matches!(result, RbfResult::Accepted { .. }));
    }

    #[test]
    fn chain_depth_limit() {
        let tx = make_tx("new", 100_000);
        let existing = vec![MempoolTxInfo {
            replacement_depth: MAX_REPLACEMENT_DEPTH,
            ..make_mempool_tx("old", 1_000)
        }];
        let result = RbfEngine::evaluate(&tx, &existing, &confirmed_keys());
        assert!(matches!(result, RbfResult::ChainTooDeep { .. }));
    }

    #[test]
    fn minimum_replacement_fee() {
        let existing = vec![make_mempool_tx("a", 1_000), make_mempool_tx("b", 2_000)];
        assert_eq!(RbfEngine::minimum_replacement_fee(&existing), 4_000); // 1000 + 2000 + 1000
    }

    #[test]
    fn all_txs_rbf_eligible() {
        let tx = make_tx("any", 100);
        assert!(RbfEngine::is_rbf_eligible(&tx));
    }

    #[test]
    fn evicts_dependents() {
        let existing = vec![MempoolTxInfo {
            dependents: vec!["child1".into(), "child2".into()],
            ..make_mempool_tx("parent", 1_000)
        }];
        let tx = make_tx("new", 10_000);
        match RbfEngine::evaluate(&tx, &existing, &confirmed_keys()) {
            RbfResult::Accepted { evicted } => {
                assert!(evicted.contains(&th("parent")));
                assert!(evicted.contains(&"child1".to_string()));
                assert!(evicted.contains(&"child2".to_string()));
            }
            _ => panic!("Should accept"),
        }
    }

    #[test]
    fn rejects_new_unconfirmed_inputs() {
        // Build a TX that spends a different input than the conflicting TX
        let unconfirmed_input_txid = th("unconfirmed_parent");
        let tx = Transaction {
            hash: th("new_with_unconfirmed"),
            inputs: vec![
                TxInput::new(th("prev"), 0, "owner".into(), "sig".into(), "pk".into()),
                TxInput::new(
                    unconfirmed_input_txid,
                    0,
                    "owner".into(),
                    "sig".into(),
                    "pk".into(),
                ),
            ],
            outputs: vec![TxOutput {
                address: "dest".into(),
                amount: 1000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 50_000,
            timestamp: 1000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let existing = vec![make_mempool_tx("old", 5_000)];
        // confirmed_keys() only contains "prev:0", so the second input is unconfirmed
        let result = RbfEngine::evaluate(&tx, &existing, &confirmed_keys());
        assert!(matches!(result, RbfResult::NewUnconfirmedInputs));
    }

    #[test]
    fn accepts_new_confirmed_inputs() {
        // Build a TX that spends an additional input that IS confirmed
        let extra_txid = th("extra_confirmed");
        let extra_key = crate::domain::utxo::utxo_set::utxo_key(&extra_txid, 0)
            .expect("test hash must be valid")
            .to_string();
        let mut keys = confirmed_keys();
        keys.insert(extra_key);

        let tx = Transaction {
            hash: th("new_with_extra"),
            inputs: vec![
                TxInput::new(th("prev"), 0, "owner".into(), "sig".into(), "pk".into()),
                TxInput::new(extra_txid, 0, "owner".into(), "sig".into(), "pk".into()),
            ],
            outputs: vec![TxOutput {
                address: "dest".into(),
                amount: 1000,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 50_000,
            timestamp: 1000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        let existing = vec![make_mempool_tx("old", 5_000)];
        let result = RbfEngine::evaluate(&tx, &existing, &keys);
        assert!(matches!(result, RbfResult::Accepted { .. }));
    }
}
