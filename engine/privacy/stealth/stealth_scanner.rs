// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════
//
// Stealth Scanner — Scans the blockchain for transactions destined to
// a specific view key holder.
//
// When an ephemeral public key R is available the scanner performs a full
// ECDH check:  ss = v*R,  P = H(ss)*G + S  and compares with the output
// address.  When R is not available (legacy txs) it falls back to a
// deterministic tag derived from the view key and tx context.
// ═══════════════════════════════════════════════════════════════════════════

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha256, Digest};

use crate::engine::privacy::stealth::view_key::ViewKey;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::block::block::Block;
use crate::errors::CryptoError;
use crate::{slog_warn, slog_error};

/// Result of scanning a transaction
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub tx_hash:  String,
    pub out_idx:  usize,
    pub address:  String,
    pub amount:   u64,
}

pub struct StealthScanner {
    pub view_key:     ViewKey,
    /// Optional spend public key for full ECDH scanning.
    pub spend_public: Option<RistrettoPoint>,
}

impl StealthScanner {
    pub fn new(view_key: ViewKey) -> Self {
        Self { view_key, spend_public: None }
    }

    /// Create a scanner with full ECDH capability.
    pub fn with_spend_public(view_key: ViewKey, spend_public: RistrettoPoint) -> Self {
        Self { view_key, spend_public: Some(spend_public) }
    }

    /// Full ECDH scan: given ephemeral pubkey R, check if an address is ours.
    ///
    /// Domain separation: tx_hash and output_index are included in the hash
    /// input so that even if the same ephemeral key were reused across
    /// transactions, each output derives a unique one-time address.  This
    /// prevents cross-transaction key reuse from leaking linkability.
    pub fn scan_with_ephemeral(
        &self,
        ephemeral_pubkey: &RistrettoPoint,
        candidate_address: &str,
        tx_hash: &str,
        output_index: usize,
    ) -> Result<bool, CryptoError> {
        let spend_pub = match &self.spend_public {
            Some(sp) => sp,
            None => return Ok(false),
        };

        // ss = v * R  (Diffie-Hellman)
        let shared_secret = self.view_key.scalar * ephemeral_pubkey;

        // hs = H(domain_tag || ss || tx_hash || output_index)
        // Domain separation: including tx_hash and output_index ensures each
        // output produces a unique derived key even with ephemeral key reuse.
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_StealthDH_v1");
        h.update(shared_secret.compress().as_bytes());
        h.update(tx_hash.as_bytes());
        h.update((output_index as u64).to_le_bytes());
        let hash: [u8; 32] = h.finalize().into();
        let hs: Scalar = Option::from(Scalar::from_canonical_bytes(hash))
            .ok_or_else(|| CryptoError::InvalidKey("Hash scalar is not canonical".to_string()))?;

        // P = hs*G + S
        let expected_pub = hs * RISTRETTO_BASEPOINT_POINT + spend_pub;

        // Derive the network prefix from the candidate address instead of
        // hardcoding "SD1s".  The scanner already filters for SD1s/ST1s/SR1s
        // in scan_transaction, so we know the prefix is one of those three.
        let prefix = if candidate_address.starts_with("ST1s") {
            "ST1s"
        } else if candidate_address.starts_with("SR1s") {
            "SR1s"
        } else {
            "SD1s"
        };

        let expected_addr = format!(
            "{}{}",
            prefix,
            hex::encode(&expected_pub.compress().as_bytes()[..20])
        );

        Ok(expected_addr == candidate_address)
    }

    /// Scan a single transaction for outputs belonging to our view key.
    /// Only outputs with an ephemeral public key are checked (full ECDH).
    /// Outputs without an ephemeral key are skipped — the weak tag fallback
    /// was removed because 8-byte tags are brute-forceable and substring
    /// matching causes unacceptable false-positive rates.
    pub fn scan_transaction(&self, tx: &Transaction) -> Vec<ScanResult> {
        use curve25519_dalek::ristretto::CompressedRistretto;

        let mut results = Vec::new();

        for (idx, output) in tx.outputs.iter().enumerate() {
            // Only stealth-prefixed addresses can be ours
            if !output.address.starts_with("SD1s")
                && !output.address.starts_with("ST1s")
                && !output.address.starts_with("SR1s")
            {
                continue;
            }

            // Require ephemeral pubkey for cryptographic ECDH scan
            let eph_hex = match &output.ephemeral_pubkey {
                Some(e) => e,
                None => {
                    slog_warn!("privacy", "stealth_no_ephemeral_pubkey", tx_hash => tx.hash, output_idx => idx);
                    continue;
                }
            };

            let eph_bytes = match hex::decode(eph_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => continue,
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&eph_bytes);
            let eph = match CompressedRistretto(arr).decompress() {
                Some(p) => p,
                None => continue,
            };

            match self.scan_with_ephemeral(&eph, &output.address, &tx.hash, idx) {
                Ok(true) => {
                    results.push(ScanResult {
                        tx_hash: tx.hash.clone(),
                        out_idx: idx,
                        address: output.address.clone(),
                        amount:  output.amount,
                    });
                }
                Ok(false) => {}
                Err(e) => {
                    slog_error!("privacy", "stealth_scan_error", tx_hash => tx.hash, output_idx => idx, error => e);
                    continue;
                }
            }
        }

        results
    }

    /// Scan a block for all matching transactions.
    pub fn scan_block(&self, block: &Block) -> Vec<ScanResult> {
        block.body.transactions.iter()
            .flat_map(|tx| self.scan_transaction(tx))
            .collect()
    }

    /// Scan blocks for stealth transactions belonging to this wallet.
    /// Uses batched processing to limit memory growth during initial sync.
    pub fn scan_blocks(&self, blocks: &[Block]) -> Vec<ScanResult> {
        const SCAN_BATCH_SIZE: usize = 100;
        let mut all_results = Vec::new();

        for chunk in blocks.chunks(SCAN_BATCH_SIZE) {
            let batch_results: Vec<ScanResult> = chunk.iter()
                .flat_map(|block| self.scan_block(block))
                .collect();
            all_results.extend(batch_results);
        }

        all_results
    }

    /// Scan a list of transactions.
    pub fn scan_block_transactions(&self, transactions: &[Transaction]) -> Vec<ScanResult> {
        transactions.iter()
            .flat_map(|tx| self.scan_transaction(tx))
            .collect()
    }

    /// Calculate total balance from scan results.
    pub fn total_balance(results: &[ScanResult]) -> u64 {
        results.iter().try_fold(0u64, |acc, r| acc.checked_add(r.amount)).unwrap_or(u64::MAX)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
//  TESTS
// ═══════════════════════════════════════════════════════════════════════════
#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::domain::address::stealth_address::StealthAddress;

    fn make_scanner() -> StealthScanner {
        StealthScanner::new(ViewKey::from_private_key("test_key").unwrap())
    }

    #[test]
    fn scan_empty_tx() {
        let scanner = make_scanner();
        let tx = Transaction {
            hash: "tx1".to_string(),
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            timestamp: 0,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        assert!(scanner.scan_transaction(&tx).is_empty());
    }

    #[test]
    fn scan_non_stealth_tx() {
        let scanner = make_scanner();
        let tx = Transaction {
            hash: "tx1".to_string(),
            inputs: vec![],
            outputs: vec![TxOutput { address: "SD1regular".into(), amount: 100, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee: 1,
            timestamp: 1000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        assert!(scanner.scan_transaction(&tx).is_empty());
    }

    #[test]
    fn total_balance_calculation() {
        let results = vec![
            ScanResult { tx_hash: "a".into(), out_idx: 0, address: "x".into(), amount: 100 },
            ScanResult { tx_hash: "b".into(), out_idx: 0, address: "y".into(), amount: 200 },
        ];
        assert_eq!(StealthScanner::total_balance(&results), 300);
    }

    #[test]
    fn ecdh_scan_detects_own_output() {
        let keys = StealthAddress::generate_keys();
        let vk = ViewKey::from_scalar(keys.view_private);
        let scanner = StealthScanner::with_spend_public(vk, keys.spend_public);

        let tx_hash = "test_tx_abc123";
        let output_index = 0usize;

        let result = StealthAddress::generate_full_with_context(
            &keys.view_public,
            &keys.spend_public,
            tx_hash,
            output_index,
        ).unwrap();

        let eph_bytes: [u8; 32] = hex::decode(&result.ephemeral_pubkey)
            .unwrap().try_into().unwrap();
        let eph = CompressedRistretto::from_slice(&eph_bytes)
            .unwrap().decompress().unwrap();

        assert!(scanner.scan_with_ephemeral(&eph, &result.one_time_address, tx_hash, output_index).unwrap());
    }

    #[test]
    fn ecdh_scan_rejects_other() {
        let alice = StealthAddress::generate_keys();
        let bob   = StealthAddress::generate_keys();

        let vk = ViewKey::from_scalar(bob.view_private);
        let scanner = StealthScanner::with_spend_public(vk, bob.spend_public);

        let result = StealthAddress::generate_full_with_context(
            &alice.view_public,
            &alice.spend_public,
            "test_tx",
            0,
        ).unwrap();

        let eph_bytes: [u8; 32] = hex::decode(&result.ephemeral_pubkey)
            .unwrap().try_into().unwrap();
        let eph = CompressedRistretto::from_slice(&eph_bytes)
            .unwrap().decompress().unwrap();

        assert!(!scanner.scan_with_ephemeral(&eph, &result.one_time_address, "test_tx", 0).unwrap());
    }
}
