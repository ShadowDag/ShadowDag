// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::collections::HashSet;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use sha2::{Sha256, Digest};

use crate::domain::transaction::transaction::{Transaction, TxInput, TxType};
use crate::domain::transaction::tx_hash::TxHash;
use crate::domain::utxo::utxo::Utxo;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::{UtxoSet, utxo_key};
use crate::config::node::node_config::NetworkMode;
use crate::engine::privacy::ringct::ring_validator::RingValidator;
use crate::errors::{StorageError, ConsensusError};

pub const MIN_TX_FEE:        u64   = 1;
pub const MAX_TX_INPUTS:     usize = 50;
pub const MAX_TX_OUTPUTS:    usize = 100;
pub const MAX_TX_BYTES:      usize = 100 * 1024;
pub const MAX_OUTPUT_AMOUNT: u64   = 21_000_000_000;
pub const DUST_LIMIT:        u64   = 546;
pub const SIGNATURE_BYTES:   usize = 64;
pub const PUBKEY_BYTES:      usize = 32;

/// Maximum age of a TX timestamp before it's rejected (24 hours).
/// Prevents replay of stale signed TXs after long delays.
pub const MAX_TX_AGE_SECS:      u64 = 24 * 3_600;
/// Maximum how far in the future a TX timestamp can be (15 seconds).
///
/// CLOCK REQUIREMENT: All nodes MUST synchronize their clocks via NTP
/// to within ±5 seconds of UTC. The 15-second window provides a 10-second
/// margin above the 5-second NTP budget. A wider window (e.g., 120s)
/// allows nodes with drifted clocks to disagree on TX validity, causing
/// mempool divergence and stale transactions sitting in some mempools
/// but rejected by others.
pub const MAX_TX_FUTURE_SECS:   u64 = 15;
/// Maximum age of the block referenced by payload_hash (48 hours in blocks).
/// At 10 BPS this is ~1.7M blocks. We check existence, not depth.
pub const PAYLOAD_HASH_HEX_LEN: usize = 64;

const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// Structural validation only (no utxo set required).
/// Checks: non-empty outputs, non-empty hash, size limits, hash integrity, output amounts.
/// Also enforces: non-coinbase tx must have >= 1 input, coinbase tx must have 0 inputs.
pub fn validate_tx(tx: &Transaction) -> bool {
    if tx.outputs.is_empty() { return false; }
    if tx.hash.is_empty() { return false; }

    // Coinbase must have exactly 0 inputs; non-coinbase must have >= 1 input
    if tx.is_coinbase() && !tx.inputs.is_empty() { return false; }
    if !tx.is_coinbase() && tx.inputs.is_empty() { return false; }

    // Use canonical_bytes for size check — matches the encoding used for
    // TX hashing, preventing size-check / hash-check mismatches.
    if tx.canonical_bytes().len() > MAX_TX_BYTES { return false; }

    if tx.inputs.len() > MAX_TX_INPUTS { return false; }
    if tx.outputs.len() > MAX_TX_OUTPUTS { return false; }

    TxValidator::sum_outputs(tx).is_some()
}

pub struct TxValidator;

impl TxValidator {

    pub fn validate_tx(tx: &Transaction, utxo_set: &UtxoSet) -> bool {

        // 🔥 FAST FAIL قبل serialize
        if tx.outputs.is_empty() { return false; }
        if tx.hash.is_empty() { return false; }

        // Use canonical_bytes for size — matches TX hash encoding
        if tx.canonical_bytes().len() > MAX_TX_BYTES { return false; }

        if !TxHash::verify(tx) {
            return false;
        }

        if tx.inputs.len() > MAX_TX_INPUTS {
            return false;
        }
        if tx.outputs.len() > MAX_TX_OUTPUTS {
            return false;
        }

        // [7] Coinbase must have 0 inputs; non-coinbase must have >= 1 input
        if tx.is_coinbase() && !tx.inputs.is_empty() {
            return false;
        }
        if tx.is_coinbase() {
            return Self::validate_outputs_only(tx);
        }
        if tx.inputs.is_empty() {
            // Non-coinbase with no inputs → reject
            return false;
        }

        let mut seen_inputs: HashSet<UtxoKey> = HashSet::with_capacity(tx.inputs.len());
        let mut input_sum:   u64             = 0;

        for input in &tx.inputs {

            let key = match utxo_key(&input.txid, input.index) {
                Ok(k) => k,
                Err(_) => return false,
            };

            if seen_inputs.contains(&key) {
                return false;
            }
            seen_inputs.insert(key);

            let utxo = match utxo_set.get_utxo(&key) {
                Some(u) => u,
                None => {
                    return false;
                }
            };

            if utxo.spent {
                return false;
            }

            // Verify that the signer owns this UTXO
            if !Self::verify_input_ownership(input, &utxo, &TxHash::signing_message(tx)) {
                return false;
            }

            input_sum = match input_sum.checked_add(utxo.amount) {
                Some(s) => s,
                None => {
                    return false;
                }
            };
        }

        let output_sum = match Self::sum_outputs(tx) {
            Some(s) => s,
            None    => return false,
        };

        if tx.fee < MIN_TX_FEE {
            return false;
        }

        let required = match output_sum.checked_add(tx.fee) {
            Some(r) => r,
            None => {
                return false;
            }
        };

        if input_sum < required {
            return false;
        }

        // Declared fee must exactly match actual fee (input_sum - output_sum).
        // Without this, a TX could declare fee=1 while the real difference is
        // much higher, enabling fee manipulation and silent miner surplus.
        let actual_fee = input_sum.saturating_sub(output_sum);
        if actual_fee != tx.fee {
            return false;
        }

        true
    }

    /// Structural validation only (no UTXO lookups) — network-aware hash verification.
    /// Used by block validator for staged UTXO validation where inputs are checked separately.
    pub fn validate_structure_for_network(tx: &Transaction, network: &NetworkMode) -> bool {
        if tx.outputs.is_empty() { return false; }
        if tx.hash.is_empty() { return false; }

        if tx.canonical_bytes().len() > MAX_TX_BYTES { return false; }

        if !TxHash::verify_for_network(tx, network) { return false; }
        if tx.inputs.len() > MAX_TX_INPUTS { return false; }
        if tx.outputs.len() > MAX_TX_OUTPUTS { return false; }

        if tx.is_coinbase() && !tx.inputs.is_empty() { return false; }
        if !tx.is_coinbase() && tx.inputs.is_empty() { return false; }

        // payload_hash format validation (if present)
        if Self::validate_payload_hash_format(tx).is_err() { return false; }

        // Check for duplicate inputs within same tx
        let mut seen: HashSet<UtxoKey> = HashSet::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let key = match utxo_key(&input.txid, input.index) {
                Ok(k) => k,
                Err(_) => return false,
            };
            if !seen.insert(key) { return false; }
        }

        // Output amounts valid
        Self::sum_outputs(tx).is_some()
    }

    /// Network-aware validation — uses the correct chain_id for hash/signature checks.
    pub fn validate_tx_for_network(tx: &Transaction, utxo_set: &UtxoSet, network: &NetworkMode) -> bool {
        // structural fast-fail (same as validate_tx)
        if tx.outputs.is_empty() { return false; }
        if tx.hash.is_empty() { return false; }

        if tx.canonical_bytes().len() > MAX_TX_BYTES { return false; }

        if !TxHash::verify_for_network(tx, network) {
            return false;
        }

        if tx.inputs.len() > MAX_TX_INPUTS { return false; }
        if tx.outputs.len() > MAX_TX_OUTPUTS { return false; }

        if tx.is_coinbase() && !tx.inputs.is_empty() { return false; }
        if tx.is_coinbase() { return Self::validate_outputs_only(tx); }
        if tx.inputs.is_empty() { return false; }

        // Anti-replay: timestamp range check
        if Self::validate_tx_timestamp(tx).is_err() { return false; }
        // Payload hash format
        if Self::validate_payload_hash_format(tx).is_err() { return false; }
        // Ring signature for confidential TXs
        if tx.is_confidential() && !RingValidator::validate(tx) { return false; }

        let mut seen_inputs: HashSet<UtxoKey> = HashSet::with_capacity(tx.inputs.len());
        let mut input_sum: u64 = 0;
        let signing_msg = TxHash::signing_message_for_network(tx, network);

        for input in &tx.inputs {
            let key = match utxo_key(&input.txid, input.index) {
                Ok(k) => k,
                Err(_) => return false,
            };

            if seen_inputs.contains(&key) { return false; }
            seen_inputs.insert(key);

            let utxo = match utxo_set.get_utxo(&key) {
                Some(u) => u,
                None => return false,
            };

            if utxo.spent { return false; }

            if !Self::verify_input_ownership(input, &utxo, &signing_msg) {
                return false;
            }

            input_sum = match input_sum.checked_add(utxo.amount) {
                Some(s) => s,
                None => return false,
            };
        }

        let output_sum = match Self::sum_outputs(tx) {
            Some(s) => s,
            None => return false,
        };

        if tx.fee < MIN_TX_FEE { return false; }

        let required = match output_sum.checked_add(tx.fee) {
            Some(r) => r,
            None => return false,
        };

        if input_sum < required {
            return false;
        }

        // Declared fee must exactly match actual fee (input_sum - output_sum).
        let actual_fee = input_sum.saturating_sub(output_sum);
        if actual_fee != tx.fee {
            return false;
        }

        true
    }

    pub fn validate(tx: &Transaction, utxo_set: &UtxoSet) -> bool {
        Self::validate_tx(tx, utxo_set)
    }

    /// Full UTXO-aware validation with descriptive error messages.
    /// Checks ALL validation gaps from issue #3:
    ///   1. Duplicate inputs within same tx
    ///   2. Input UTXO must exist
    ///   3. Input UTXO must be unspent
    ///   4. sum(inputs) >= sum(outputs)
    ///   5. Overflow protection via checked_add
    ///   6. Non-negative fee (inputs - outputs >= 0)
    ///   7. Empty inputs/outputs rejection (non-coinbase)
    ///   8. TX timestamp within acceptable range (anti-replay)
    ///   9. payload_hash format validation (anti-replay)
    pub fn validate_transaction(tx: &Transaction, utxo_set: &UtxoSet) -> Result<(), StorageError> {
        // ── structural checks ───────────────────────────────────────────
        if tx.hash.is_empty() {
            return Err(StorageError::Other("transaction hash is empty".into()));
        }
        if tx.outputs.is_empty() {
            return Err(StorageError::Other("transaction has no outputs".into()));
        }

        // [8] TX timestamp validation — reject stale/future TXs
        if let Err(reason) = Self::validate_tx_timestamp(tx) {
            return Err(StorageError::Other(format!("tx {}: {}", tx.hash, reason)));
        }

        // [9] payload_hash format validation
        if let Err(reason) = Self::validate_payload_hash_format(tx) {
            return Err(StorageError::Other(format!("tx {}: {}", tx.hash, reason)));
        }

        // Size limit — use canonical_bytes (matches TX hash encoding)
        let canonical_size = tx.canonical_bytes().len();
        if canonical_size > MAX_TX_BYTES {
            return Err(StorageError::Other(format!("transaction exceeds max size ({} > {})", canonical_size, MAX_TX_BYTES)));
        }

        if tx.inputs.len() > MAX_TX_INPUTS {
            return Err(StorageError::Other(format!("too many inputs ({} > {})", tx.inputs.len(), MAX_TX_INPUTS)));
        }
        if tx.outputs.len() > MAX_TX_OUTPUTS {
            return Err(StorageError::Other(format!("too many outputs ({} > {})", tx.outputs.len(), MAX_TX_OUTPUTS)));
        }

        // ── [7] coinbase must have 0 inputs; non-coinbase must have >= 1 ──
        if tx.is_coinbase() && !tx.inputs.is_empty() {
            return Err(StorageError::Other("coinbase transaction must have exactly 0 inputs".into()));
        }
        if !tx.is_coinbase() && tx.inputs.is_empty() {
            return Err(StorageError::Other("non-coinbase transaction has no inputs".into()));
        }

        // ── output validation (overflow-safe) ───────────────────────────
        let output_sum = Self::sum_outputs(tx)
            .ok_or_else(|| StorageError::Other("output amount invalid (dust/overflow/exceeds max)".to_string()))?;

        // Coinbase: only output validation needed
        if tx.is_coinbase() {
            return Ok(());
        }

        // ── [1][2][3][5] input validation ───────────────────────────────
        let mut seen_inputs: HashSet<UtxoKey> = HashSet::with_capacity(tx.inputs.len());
        let mut input_sum: u64 = 0;

        for input in &tx.inputs {
            let key = utxo_key(&input.txid, input.index)?;

            // [1] Duplicate inputs within same tx
            if !seen_inputs.insert(key) {
                return Err(StorageError::Other(format!("duplicate input {} in transaction {}", key, tx.hash)));
            }

            // [2] Input UTXO must exist
            let utxo = utxo_set.get_utxo(&key)
                .ok_or_else(|| StorageError::KeyNotFound(format!("input utxo {} not found (tx {})", key, tx.hash)))?;

            // [3] Input UTXO must be unspent
            if utxo.spent {
                return Err(StorageError::Other(format!("input utxo {} already spent (tx {})", key, tx.hash)));
            }

            // [NEW] Verify signature matches UTXO owner
            let signing_msg = TxHash::signing_message(tx);
            if !Self::verify_input_ownership(input, &utxo, &signing_msg) {
                return Err(StorageError::Other(format!(
                    "input {} signature does not match UTXO owner (tx {})", key, tx.hash
                )));
            }

            // [5] Overflow protection
            input_sum = input_sum.checked_add(utxo.amount)
                .ok_or_else(|| StorageError::Other(format!("input sum overflow at utxo {} (tx {})", key, tx.hash)))?;
        }

        // ── [4][6] amount and fee checks ────────────────────────────────
        // [4] inputs >= outputs
        if input_sum < output_sum {
            return Err(StorageError::Other(format!(
                "inputs ({}) < outputs ({}) in tx {}",
                input_sum, output_sum, tx.hash
            )));
        }

        // [6] Negative fee detection: fee field must match actual fee
        let actual_fee = input_sum.checked_sub(output_sum)
            .ok_or_else(|| StorageError::Other(format!("fee underflow in tx {}", tx.hash)))?;

        if actual_fee < MIN_TX_FEE {
            return Err(StorageError::Other(format!(
                "fee too low ({} < {}) in tx {}",
                actual_fee, MIN_TX_FEE, tx.hash
            )));
        }

        // Declared fee MUST exactly equal the actual fee (input_sum - output_sum).
        // Without this check, a TX could declare fee=1 while the real difference
        // is 1000, allowing fee manipulation for mempool priority ordering and
        // letting miners silently pocket undeclared surplus.
        if actual_fee != tx.fee {
            return Err(StorageError::Other(format!(
                "declared fee ({}) != actual fee ({}) in tx {}",
                tx.fee, actual_fee, tx.hash
            )));
        }

        // ── Ring signature verification for confidential transactions ───
        // Mandatory check: ring signatures must be valid in the consensus path.
        // block_validator already checks this, but tx_validator must also enforce
        // it so that mempool admission and standalone TX validation are safe.
        if tx.is_confidential()
            && !RingValidator::validate(tx) {
                return Err(StorageError::Other(format!(
                    "ring signature verification failed for confidential tx {}",
                    tx.hash
                )));
            }

        Ok(())
    }

    /// Verify that the input's signature was produced by the UTXO's owner.
    /// The signing message should be the transaction's canonical signing hash.
    /// Steps:
    ///   1. Decode and validate the public key from the input
    ///   2. Derive the address from that public key
    ///   3. Check the derived address matches the UTXO's owner/address
    ///   4. Verify the signature against the signing message
    pub fn verify_input_ownership(input: &TxInput, utxo: &Utxo, signing_msg: &[u8]) -> bool {
        if input.signature.is_empty() || input.pub_key.is_empty() {
            return false;
        }

        // Decode public key
        let pk_arr: [u8; 32] = match hex::decode(&input.pub_key) {
            Ok(b) if b.len() == PUBKEY_BYTES => {
                match b.try_into() { Ok(a) => a, Err(_) => return false }
            }
            _ => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Derive address from public key (canonical format from domain::address::Address)
        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, b"ShadowDAG_Addr_v1");
        Digest::update(&mut h, pk_arr);
        let hash = Digest::finalize(h);
        let addr_hex = hex::encode(&hash[..20]);

        // Determine network prefix from the UTXO's address to ensure correct matching
        let prefix = if utxo.address.starts_with("ST1") || utxo.owner.starts_with("ST1") {
            "ST1"
        } else if utxo.address.starts_with("SR1") || utxo.owner.starts_with("SR1") {
            "SR1"
        } else {
            "SD1"
        };
        let derived_address = format!("{}{}", prefix, addr_hex);

        // Single canonical ownership check: derived address MUST match utxo.owner.
        // This is the only valid proof that the signer owns the UTXO.
        if derived_address != utxo.owner {
            return false;
        }

        // Decode and verify signature
        let sig_bytes: [u8; 64] = match hex::decode(&input.signature) {
            Ok(b) if b.len() == SIGNATURE_BYTES => {
                match b.try_into() { Ok(a) => a, Err(_) => return false }
            }
            _ => return false,
        };

        if !Self::s_is_canonical(&sig_bytes[32..]) {
            return false;
        }

        let signature = Signature::from_bytes(&sig_bytes);
        // verify_strict: prevents signature malleability by rejecting
        // non-canonical signatures. Without this, the same tx could have
        // multiple valid signature encodings → different hashes → bypass tx_seen.
        verifying_key.verify_strict(signing_msg, &signature).is_ok()
    }

    /// Verify input ownership against a known owner address (for staged/intra-block UTXOs).
    /// Same logic as verify_input_ownership but takes an address string instead of a Utxo.
    pub fn verify_input_ownership_by_address(input: &TxInput, owner_address: &str, signing_msg: &[u8]) -> bool {
        if input.signature.is_empty() || input.pub_key.is_empty() {
            return false;
        }

        // Decode public key
        let pk_arr: [u8; 32] = match hex::decode(&input.pub_key) {
            Ok(b) if b.len() == PUBKEY_BYTES => {
                match b.try_into() { Ok(a) => a, Err(_) => return false }
            }
            _ => return false,
        };

        let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
            Ok(k) => k,
            Err(_) => return false,
        };

        // Derive address from public key
        let mut h = <Sha256 as Digest>::new();
        Digest::update(&mut h, b"ShadowDAG_Addr_v1");
        Digest::update(&mut h, pk_arr);
        let hash = Digest::finalize(h);
        let addr_hex = hex::encode(&hash[..20]);

        // Determine network prefix from the owner address
        let prefix = if owner_address.starts_with("ST1") {
            "ST1"
        } else if owner_address.starts_with("SR1") {
            "SR1"
        } else {
            "SD1"
        };
        let derived_address = format!("{}{}", prefix, addr_hex);

        // Check that the derived address matches the owner
        if derived_address != owner_address {
            return false;
        }

        // Decode and verify signature
        let sig_bytes: [u8; 64] = match hex::decode(&input.signature) {
            Ok(b) if b.len() == SIGNATURE_BYTES => {
                match b.try_into() { Ok(a) => a, Err(_) => return false }
            }
            _ => return false,
        };

        if !Self::s_is_canonical(&sig_bytes[32..]) {
            return false;
        }

        let signature = Signature::from_bytes(&sig_bytes);
        // verify_strict: prevents signature malleability by rejecting
        // non-canonical signatures. Without this, the same tx could have
        // multiple valid signature encodings → different hashes → bypass tx_seen.
        verifying_key.verify_strict(signing_msg, &signature).is_ok()
    }

    pub fn verify_signatures(tx: &Transaction) -> bool {
        Self::verify_signatures_for_network(tx, &NetworkMode::Mainnet)
    }

    /// Network-aware signature verification -- uses the correct chain_id for
    /// the signing message so that testnet/regtest signatures are verified
    /// against the right message.
    pub fn verify_signatures_for_network(tx: &Transaction, network: &NetworkMode) -> bool {
        if tx.inputs.is_empty() { return true; }

        let msg = TxHash::signing_message_for_network(tx, network);

        for input in &tx.inputs {
            if input.signature.is_empty() { return false; }
            if input.pub_key.is_empty() { return false; }

            let sig_bytes: [u8; 64] = match hex::decode(&input.signature) {
                Ok(b) if b.len() == SIGNATURE_BYTES => {
                    match b.try_into() { Ok(a) => a, Err(_) => return false }
                }
                _ => return false,
            };

            if !Self::s_is_canonical(&sig_bytes[32..]) {
                return false;
            }

            let pk_arr: [u8; 32] = match hex::decode(&input.pub_key) {
                Ok(b) if b.len() == PUBKEY_BYTES => {
                    match b.try_into() { Ok(a) => a, Err(_) => return false }
                }
                _ => return false,
            };

            let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
                Ok(k) => k,
                Err(_) => return false,
            };

            let signature = Signature::from_bytes(&sig_bytes);

            if verifying_key.verify(&msg, &signature).is_err() {
                return false;
            }
        }

        true
    }

    pub fn build_signing_message(tx: &Transaction) -> Vec<u8> {
        TxHash::signing_message(tx)
    }

    /// Validate TX timestamp is within acceptable range of current time.
    /// Rejects TXs older than MAX_TX_AGE_SECS or more than MAX_TX_FUTURE_SECS
    /// in the future. Coinbase TXs are exempt (their timestamp comes from
    /// the block header which has its own validation).
    pub fn validate_tx_timestamp(tx: &Transaction) -> Result<(), ConsensusError> {
        if tx.is_coinbase() {
            return Ok(());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if tx.timestamp > now + MAX_TX_FUTURE_SECS {
            return Err(ConsensusError::Timestamp(format!(
                "tx timestamp {} is {}s in the future (max {}s)",
                tx.timestamp, tx.timestamp - now, MAX_TX_FUTURE_SECS
            )));
        }

        if now > tx.timestamp && (now - tx.timestamp) > MAX_TX_AGE_SECS {
            return Err(ConsensusError::Timestamp(format!(
                "tx timestamp {} is {}s old (max {}s)",
                tx.timestamp, now - tx.timestamp, MAX_TX_AGE_SECS
            )));
        }

        Ok(())
    }

    /// Validate the payload_hash field if present.
    /// The payload_hash must be a valid 64-char hex string (32-byte block hash).
    /// The caller is responsible for checking block existence (requires chain state).
    pub fn validate_payload_hash_format(tx: &Transaction) -> Result<(), ConsensusError> {
        if let Some(ref ph) = tx.payload_hash {
            if ph.len() != PAYLOAD_HASH_HEX_LEN {
                return Err(ConsensusError::BlockValidation(format!(
                    "payload_hash length {} != expected {}",
                    ph.len(), PAYLOAD_HASH_HEX_LEN
                )));
            }
            if !ph.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ConsensusError::BlockValidation(
                    "payload_hash contains non-hex characters".into(),
                ));
            }
        }
        Ok(())
    }

    /// Check that S < L (Ed25519 group order).
    /// Ed25519 scalars are little-endian, so we compare from byte 31 (MSB) down to byte 0 (LSB).
    pub fn s_is_canonical(s_bytes: &[u8]) -> bool {
        if s_bytes.len() < 32 { return false; }

        // Compare from MSB (byte 31) to LSB (byte 0) for little-endian scalar
        for i in (0..32).rev() {
            if s_bytes[i] < ED25519_L[i] { return true; }
            if s_bytes[i] > ED25519_L[i] { return false; }
        }
        false // Equal to L is not canonical
    }

    fn validate_outputs_only(tx: &Transaction) -> bool {
        Self::sum_outputs(tx).is_some()
    }

    fn sum_outputs(tx: &Transaction) -> Option<u64> {
        let mut total: u64 = 0;

        for output in &tx.outputs {
            if output.amount < DUST_LIMIT { return None; }
            if output.amount > MAX_OUTPUT_AMOUNT { return None; }

            total = total.checked_add(output.amount)?;
        }

        Some(total)
    }

    /// Validate swap transaction payload fields.
    /// Returns Ok(()) if the HTLC secret hash is well-formed.
    pub fn validate_swap_payload(tx: &Transaction) -> Result<(), ConsensusError> {
        if tx.tx_type != TxType::SwapTx {
            return Ok(()); // Not a swap tx, skip
        }
        let hash = match &tx.payload_hash {
            Some(h) => h,
            None => return Err(ConsensusError::BlockValidation("SwapTx requires payload_hash".into())),
        };
        if hash.len() != 64 {
            return Err(ConsensusError::BlockValidation(
                format!("SwapTx payload_hash length {} != 64", hash.len())
            ));
        }
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ConsensusError::BlockValidation("SwapTx payload_hash contains non-hex chars".into()));
        }
        Ok(())
    }

    /// Validate DEX order transaction payload fields.
    pub fn validate_dex_order_payload(tx: &Transaction) -> Result<(), ConsensusError> {
        if tx.tx_type != TxType::DexOrder {
            return Ok(()); // Not a dex order, skip
        }
        let data = match &tx.payload_hash {
            Some(d) => d,
            None => return Err(ConsensusError::BlockValidation("DexOrder requires payload_hash".into())),
        };
        if data.is_empty() {
            return Err(ConsensusError::BlockValidation("DexOrder payload_hash is empty".into()));
        }
        if !data.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ConsensusError::BlockValidation("DexOrder payload_hash contains non-hex chars".into()));
        }
        Ok(())
    }
}