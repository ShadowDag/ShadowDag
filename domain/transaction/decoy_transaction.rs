// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use rand::seq::SliceRandom;
use rand::Rng;

use crate::domain::transaction::transaction::Transaction;

#[derive(Clone)]
pub struct DecoyTransaction {
    pub tx: Transaction,

    pub is_decoy: bool,

    pub ring_index: usize,
}

impl DecoyTransaction {
    pub fn new_real(tx: Transaction, ring_index: usize) -> Self {
        Self {
            tx,
            is_decoy: false,
            ring_index,
        }
    }

    pub fn new_decoy(tx: Transaction, ring_index: usize) -> Self {
        Self {
            tx,
            is_decoy: true,
            ring_index,
        }
    }

    pub fn is_fake(&self) -> bool {
        self.is_decoy
    }
}

pub struct Ring {
    pub members: Vec<DecoyTransaction>,
    pub ring_size: usize,
}

impl Ring {
    pub fn generate(real_tx: Transaction, pool: &[Transaction], ring_size: usize) -> Self {
        let mut rng = rand::thread_rng();

        let actual_size = ring_size.max(1).min(pool.len() + 1);
        let mut members = Vec::with_capacity(actual_size);

        // Randomly sample decoys from pool instead of taking first N
        let decoys_needed = actual_size.saturating_sub(1);
        let mut candidates: Vec<&Transaction> =
            pool.iter().filter(|tx| tx.hash != real_tx.hash).collect();
        candidates.shuffle(&mut rng);
        for (i, tx) in candidates.into_iter().take(decoys_needed).enumerate() {
            members.push(DecoyTransaction::new_decoy(tx.clone(), i));
        }

        // Insert real TX at a random position (not deterministic middle)
        let real_pos = rng.gen_range(0..=members.len());
        members.insert(real_pos, DecoyTransaction::new_real(real_tx, real_pos));

        // Re-index all members after insertion
        for (i, m) in members.iter_mut().enumerate() {
            m.ring_index = i;
        }

        let ring_size = members.len();

        Self { members, ring_size }
    }

    pub fn is_valid(&self) -> bool {
        let real_count = self.members.iter().filter(|m| !m.is_decoy).count();
        real_count == 1 && !self.members.is_empty()
    }

    pub fn get_real(&self) -> Option<&Transaction> {
        self.members.iter().find(|m| !m.is_decoy).map(|m| &m.tx)
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};

    fn make_tx(hash: &str) -> Transaction {
        Transaction {
            hash: hash.to_string(),
            inputs: vec![],
            outputs: vec![TxOutput {
                address: "addr".into(),
                amount: 10,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 1,
            timestamp: 1735689600,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    #[test]
    fn ring_has_exactly_one_real() {
        let real = make_tx("real_tx");
        let pool: Vec<_> = (0..5).map(|i| make_tx(&format!("decoy_{}", i))).collect();
        let ring = Ring::generate(real, &pool, 3);
        assert!(ring.is_valid());
        assert_eq!(ring.members.iter().filter(|m| !m.is_decoy).count(), 1);
    }

    #[test]
    fn ring_get_real_returns_correct_tx() {
        let real = make_tx("my_real_tx");
        let pool: Vec<_> = (0..3).map(|i| make_tx(&format!("d{}", i))).collect();
        let ring = Ring::generate(real, &pool, 3);
        let found = ring.get_real().unwrap();
        assert_eq!(found.hash, "my_real_tx");
    }

    #[test]
    fn empty_pool_ring_has_one_member() {
        let real = make_tx("only_tx");
        let ring = Ring::generate(real, &[], 5);
        assert_eq!(ring.len(), 1);
        assert!(ring.is_valid());
    }
}
