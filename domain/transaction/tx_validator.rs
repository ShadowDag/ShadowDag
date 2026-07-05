// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use crate::config::node::node_config::NetworkMode;
use crate::domain::transaction::transaction::{Transaction, TxInput, TxType};
use crate::domain::transaction::tx_hash::TxHash;
use crate::domain::utxo::utxo::Utxo;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::{utxo_key, UtxoSet};
use crate::errors::{ConsensusError, StorageError};

pub const MIN_TX_FEE: u64 = 1;
pub const MAX_TX_INPUTS: usize = 50;
pub const MAX_TX_OUTPUTS: usize = 100;
pub const MAX_TX_BYTES: usize = 100 * 1024;
pub const MAX_OUTPUT_AMOUNT: u64 = 21_000_000_000;
pub const DUST_LIMIT: u64 = 546;
pub const SIGNATURE_BYTES: usize = 64;
pub const PUBKEY_BYTES: usize = 32;

/// Maximum age of a TX timestamp before it's rejected (24 hours), in MILLISECONDS.
/// TX timestamps are unix epoch ms (migrated with block timestamps). Prevents
/// replay of stale signed TXs after long delays.
pub const MAX_TX_AGE_MS: u64 = 24 * 3_600 * 1_000;
/// Maximum how far in the future a TX timestamp can be (15 seconds), in MILLISECONDS.
///
/// CLOCK REQUIREMENT: All nodes MUST synchronize their clocks via NTP
/// to within ±5 seconds of UTC. The 15-second window provides a 10-second
/// margin above the 5-second NTP budget. A wider window (e.g., 120s)
/// allows nodes with drifted clocks to disagree on TX validity, causing
/// mempool divergence and stale transactions sitting in some mempools
/// but rejected by others. MUST match block_validator's MAX_TX_FUTURE_MS
/// (tx ts is compared to block ts there).
pub const MAX_TX_FUTURE_MS: u64 = 15_000;
/// Maximum age of the block referenced by payload_hash (48 hours in blocks).
/// At 10 BPS this is ~1.7M blocks. We check existence, not depth.
pub const PAYLOAD_HASH_HEX_LEN: usize = 64;

const ED25519_L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[inline]
fn infer_network_from_tx_free(tx: &Transaction) -> NetworkMode {
    for output in &tx.outputs {
        if output.address.starts_with("ST1") {
            return NetworkMode::Testnet;
        }
        if output.address.starts_with("SR1") {
            return NetworkMode::Regtest;
        }
        if output.address.starts_with("SD1") {
            return NetworkMode::Mainnet;
        }
    }
    for input in &tx.inputs {
        if input.owner.starts_with("ST1") {
            return NetworkMode::Testnet;
        }
        if input.owner.starts_with("SR1") {
            return NetworkMode::Regtest;
        }
        if input.owner.starts_with("SD1") {
            return NetworkMode::Mainnet;
        }
    }
    NetworkMode::Mainnet
}

#[inline]
fn tx_addresses_match_network_free(tx: &Transaction, network: &NetworkMode) -> bool {
    for output in &tx.outputs {
        if output.address.starts_with("ST1") && !matches!(network, NetworkMode::Testnet) {
            return false;
        }
        if output.address.starts_with("SR1") && !matches!(network, NetworkMode::Regtest) {
            return false;
        }
        if output.address.starts_with("SD1") && !matches!(network, NetworkMode::Mainnet) {
            return false;
        }
    }
    for input in &tx.inputs {
        if input.owner.starts_with("ST1") && !matches!(network, NetworkMode::Testnet) {
            return false;
        }
        if input.owner.starts_with("SR1") && !matches!(network, NetworkMode::Regtest) {
            return false;
        }
        if input.owner.starts_with("SD1") && !matches!(network, NetworkMode::Mainnet) {
            return false;
        }
    }
    true
}

/// Structural validation only (no utxo set required).
/// Checks: non-empty outputs, non-empty hash, size limits, hash integrity, output amounts.
/// Also enforces: non-coinbase tx must have >= 1 input, coinbase tx must have 0 inputs.
pub fn validate_tx(tx: &Transaction) -> bool {
    if tx.outputs.is_empty() {
        return false;
    }
    if tx.hash.is_empty() {
        return false;
    }
    let network = infer_network_from_tx_free(tx);
    if !tx_addresses_match_network_free(tx, &network) {
        return false;
    }

    if !tx.is_coinbase() && !TxHash::verify_for_network(tx, &network) {
        return false;
    }

    // Coinbase must have exactly 0 inputs; non-coinbase must have >= 1 input
    if tx.is_coinbase() && !tx.inputs.is_empty() {
        return false;
    }
    if !tx.is_coinbase() && tx.inputs.is_empty() {
        return false;
    }

    // Use canonical_bytes for size check — matches the encoding used for
    // TX hashing, preventing size-check / hash-check mismatches.
    if tx.canonical_bytes().len() > MAX_TX_BYTES {
        return false;
    }

    if tx.inputs.len() > MAX_TX_INPUTS {
        return false;
    }
    if tx.outputs.len() > MAX_TX_OUTPUTS {
        return false;
    }

    TxValidator::sum_outputs(tx).is_some()
}

pub struct TxValidator;

impl TxValidator {
    #[inline]
    fn contract_prefix_for_network(network: &NetworkMode) -> &'static str {
        match network {
            NetworkMode::Mainnet => "SD1c",
            NetworkMode::Testnet => "ST1c",
            NetworkMode::Regtest => "SR1c",
        }
    }

    #[inline]
    fn infer_network_from_address(addr: &str) -> Option<NetworkMode> {
        if addr.starts_with("ST1") {
            Some(NetworkMode::Testnet)
        } else if addr.starts_with("SR1") {
            Some(NetworkMode::Regtest)
        } else if addr.starts_with("SD1") {
            Some(NetworkMode::Mainnet)
        } else {
            None
        }
    }

    #[inline]
    fn infer_network_from_tx(tx: &Transaction, utxo_set: Option<&UtxoSet>) -> NetworkMode {
        for output in &tx.outputs {
            if let Some(n) = Self::infer_network_from_address(&output.address) {
                return n;
            }
        }
        if let Some(set) = utxo_set {
            for input in &tx.inputs {
                if let Ok(key) = utxo_key(&input.txid, input.index) {
                    if let Some(utxo) = set.get_utxo(&key) {
                        if let Some(n) = Self::infer_network_from_address(&utxo.address) {
                            return n;
                        }
                    }
                }
                if let Some(n) = Self::infer_network_from_address(&input.owner) {
                    return n;
                }
            }
        }
        NetworkMode::Mainnet
    }

    #[inline]
    fn tx_addresses_match_network(
        tx: &Transaction,
        network: &NetworkMode,
        utxo_set: Option<&UtxoSet>,
    ) -> bool {
        for output in &tx.outputs {
            if let Some(n) = Self::infer_network_from_address(&output.address) {
                if &n != network {
                    return false;
                }
            }
        }

        for input in &tx.inputs {
            if let Some(n) = Self::infer_network_from_address(&input.owner) {
                if &n != network {
                    return false;
                }
            }
        }

        if let Some(set) = utxo_set {
            for input in &tx.inputs {
                let key = match utxo_key(&input.txid, input.index) {
                    Ok(k) => k,
                    Err(_) => return false,
                };
                if let Some(utxo) = set.get_utxo(&key) {
                    if let Some(n) = Self::infer_network_from_address(&utxo.address) {
                        if &n != network {
                            return false;
                        }
                    }
                    if let Some(n) = Self::infer_network_from_address(&utxo.owner) {
                        if &n != network {
                            return false;
                        }
                    }
                }
            }
        }

        true
    }
    pub fn validate_tx(tx: &Transaction, utxo_set: &UtxoSet) -> bool {
        // 🔥 FAST FAIL قبل serialize
        if tx.outputs.is_empty() {
            return false;
        }
        if tx.hash.is_empty() {
            return false;
        }

        // Use canonical_bytes for size — matches TX hash encoding
        if tx.canonical_bytes().len() > MAX_TX_BYTES {
            return false;
        }

        let network = Self::infer_network_from_tx(tx, Some(utxo_set));
        if !Self::tx_addresses_match_network(tx, &network, Some(utxo_set)) {
            return false;
        }

        if !TxHash::verify_for_network(tx, &network) {
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
        let mut input_sum: u64 = 0;
        let signing_msg = TxHash::signing_message_for_network(tx, &network);

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
            if !Self::verify_input_ownership(input, &utxo, &signing_msg) {
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
            None => return false,
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
        if tx.outputs.is_empty() {
            return false;
        }
        if tx.hash.is_empty() {
            return false;
        }

        if tx.canonical_bytes().len() > MAX_TX_BYTES {
            return false;
        }

        if !TxHash::verify_for_network(tx, network) {
            return false;
        }
        if !Self::tx_addresses_match_network(tx, network, None) {
            return false;
        }
        if tx.inputs.len() > MAX_TX_INPUTS {
            return false;
        }
        if tx.outputs.len() > MAX_TX_OUTPUTS {
            return false;
        }

        if tx.is_coinbase() && !tx.inputs.is_empty() {
            return false;
        }
        if !tx.is_coinbase() && tx.inputs.is_empty() {
            return false;
        }

        // payload_hash format validation (if present)
        if Self::validate_payload_hash_format(tx).is_err() {
            return false;
        }

        // Contract-specific payload validation
        if Self::validate_contract_create_payload_for_network(tx, network).is_err() {
            return false;
        }
        if Self::validate_contract_call_payload_for_network(tx, network).is_err() {
            return false;
        }

        // Check for duplicate inputs within same tx
        let mut seen: HashSet<UtxoKey> = HashSet::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let key = match utxo_key(&input.txid, input.index) {
                Ok(k) => k,
                Err(_) => return false,
            };
            if !seen.insert(key) {
                return false;
            }
        }

        // Output amounts valid
        Self::sum_outputs(tx).is_some()
    }

    /// Network-aware validation — uses the correct chain_id for hash/signature checks.
    pub fn validate_tx_for_network(
        tx: &Transaction,
        utxo_set: &UtxoSet,
        network: &NetworkMode,
    ) -> bool {
        // structural fast-fail (same as validate_tx)
        if tx.outputs.is_empty() {
            return false;
        }
        if tx.hash.is_empty() {
            return false;
        }

        if tx.canonical_bytes().len() > MAX_TX_BYTES {
            return false;
        }

        if !TxHash::verify_for_network(tx, network) {
            return false;
        }
        if !Self::tx_addresses_match_network(tx, network, Some(utxo_set)) {
            return false;
        }

        if tx.inputs.len() > MAX_TX_INPUTS {
            return false;
        }
        if tx.outputs.len() > MAX_TX_OUTPUTS {
            return false;
        }

        if tx.is_coinbase() && !tx.inputs.is_empty() {
            return false;
        }
        if tx.is_coinbase() {
            return Self::validate_outputs_only(tx);
        }
        if tx.inputs.is_empty() {
            return false;
        }

        // Anti-replay: timestamp range check
        if Self::validate_tx_timestamp(tx).is_err() {
            return false;
        }
        // Payload hash format
        if Self::validate_payload_hash_format(tx).is_err() {
            return false;
        }
        // Contract-specific payload validation
        if Self::validate_contract_create_payload_for_network(tx, network).is_err() {
            return false;
        }
        if Self::validate_contract_call_payload_for_network(tx, network).is_err() {
            return false;
        }
        // Confidential (RingCT) TXs are validated ENTIRELY by the confidential
        // gate (CLSAG + on-chain ring authenticity + key-image uniqueness +
        // homomorphic balance + range proofs) and then RETURN — they must NOT
        // fall through to the transparent UTXO loop below, which would look up
        // a non-existent outpoint (confidential inputs carry a dummy txid) and
        // reject the tx, diverging from the block path (validate_block_utxos).
        if tx.is_confidential() {
            return Self::validate_confidential(tx, utxo_set, network);
        }
        // Shield: transparent inputs -> confidential outputs. Validated entirely
        // by the shield gate and RETURNS (its outputs are confidential; falling
        // through to the transparent output/balance logic would misjudge it).
        if tx.is_shield() {
            return Self::validate_shield(tx, utxo_set, network);
        }

        let mut seen_inputs: HashSet<UtxoKey> = HashSet::with_capacity(tx.inputs.len());
        let mut input_sum: u64 = 0;
        let signing_msg = TxHash::signing_message_for_network(tx, network);

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
                None => return false,
            };

            if utxo.spent {
                return false;
            }

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

        if tx.fee < MIN_TX_FEE {
            return false;
        }

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
        let network = Self::infer_network_from_tx(tx, Some(utxo_set));
        Self::validate_tx_for_network(tx, utxo_set, &network)
    }

    /// Full confidential (RingCT) validation for the mempool path. Delegates to
    /// the SAME gate the block path uses (`verify_confidential_tx`): dual-key
    /// CLSAG + on-chain ring-member authenticity (P AND C) + key-image
    /// uniqueness + per-output range proofs + homomorphic balance
    /// `Σ C'_in == Σ C_out + fee·H`. Mempool and block share one code path, so
    /// they cannot diverge.
    pub fn validate_confidential(
        tx: &Transaction,
        utxo_set: &UtxoSet,
        network: &NetworkMode,
    ) -> bool {
        let mut seen = std::collections::HashSet::new();
        crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx(
            tx, utxo_set, network, &mut seen,
        )
        .is_ok()
    }

    /// Validate a SHIELD tx (transparent inputs -> confidential outputs) through
    /// the shared shield gate — the SAME `verify_shield_tx` used on the block and
    /// reorg paths, so mempool/block/reorg all agree.
    pub fn validate_shield(tx: &Transaction, utxo_set: &UtxoSet, network: &NetworkMode) -> bool {
        crate::engine::privacy::ringct::confidential_consensus::verify_shield_tx(
            tx, utxo_set, network,
        )
        .is_ok()
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
        let network = Self::infer_network_from_tx(tx, Some(utxo_set));
        if !Self::tx_addresses_match_network(tx, &network, Some(utxo_set)) {
            return Err(StorageError::Other(
                "transaction mixes addresses from different networks".into(),
            ));
        }
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

        // Bind tx.hash to canonical content BEFORE the confidential/shield
        // early-returns — otherwise those paths never check txid == canonical
        // bytes and a mismatched/forged txid would slip through. Matches
        // validate_tx_for_network's ordering (hash check before the branches).
        if !TxHash::verify_for_network(tx, &network) {
            return Err(StorageError::Other(format!(
                "transaction hash verification failed for {}",
                tx.hash
            )));
        }

        // Confidential (RingCT) TXs: validated entirely by the confidential gate
        // and RETURN — must not fall through to the transparent UTXO loop below
        // (their inputs carry dummy outpoints). Mirrors validate_tx_for_network
        // and the block path (validate_block_utxos).
        if tx.is_confidential() {
            return if Self::validate_confidential(tx, utxo_set, &network) {
                Ok(())
            } else {
                Err(StorageError::Other(format!(
                    "confidential (RingCT) verification failed for tx {}",
                    tx.hash
                )))
            };
        }
        // Shield (transparent -> confidential): shared shield gate, then RETURN.
        if tx.is_shield() {
            return if Self::validate_shield(tx, utxo_set, &network) {
                Ok(())
            } else {
                Err(StorageError::Other(format!(
                    "shield verification failed for tx {}",
                    tx.hash
                )))
            };
        }

        // [9] payload_hash format validation
        if let Err(reason) = Self::validate_payload_hash_format(tx) {
            return Err(StorageError::Other(format!("tx {}: {}", tx.hash, reason)));
        }

        // [10] Contract-specific payload validation
        if let Err(reason) = Self::validate_contract_create_payload_for_network(tx, &network) {
            return Err(StorageError::Other(format!("tx {}: {}", tx.hash, reason)));
        }
        if let Err(reason) = Self::validate_contract_call_payload_for_network(tx, &network) {
            return Err(StorageError::Other(format!("tx {}: {}", tx.hash, reason)));
        }

        // Size limit — use canonical_bytes (matches TX hash encoding)
        let canonical_size = tx.canonical_bytes().len();
        if canonical_size > MAX_TX_BYTES {
            return Err(StorageError::Other(format!(
                "transaction exceeds max size ({} > {})",
                canonical_size, MAX_TX_BYTES
            )));
        }

        // (tx.hash canonical binding already verified above, before the
        // confidential/shield branches.)

        if tx.inputs.len() > MAX_TX_INPUTS {
            return Err(StorageError::Other(format!(
                "too many inputs ({} > {})",
                tx.inputs.len(),
                MAX_TX_INPUTS
            )));
        }
        if tx.outputs.len() > MAX_TX_OUTPUTS {
            return Err(StorageError::Other(format!(
                "too many outputs ({} > {})",
                tx.outputs.len(),
                MAX_TX_OUTPUTS
            )));
        }

        // ── [7] coinbase must have 0 inputs; non-coinbase must have >= 1 ──
        if tx.is_coinbase() && !tx.inputs.is_empty() {
            return Err(StorageError::Other(
                "coinbase transaction must have exactly 0 inputs".into(),
            ));
        }
        if !tx.is_coinbase() && tx.inputs.is_empty() {
            return Err(StorageError::Other(
                "non-coinbase transaction has no inputs".into(),
            ));
        }

        // ── output validation (overflow-safe) ───────────────────────────
        let output_sum = Self::sum_outputs(tx).ok_or_else(|| {
            StorageError::Other("output amount invalid (dust/overflow/exceeds max)".to_string())
        })?;

        // Coinbase: only output validation needed
        if tx.is_coinbase() {
            return Ok(());
        }

        // ── [1][2][3][5] input validation ───────────────────────────────
        let mut seen_inputs: HashSet<UtxoKey> = HashSet::with_capacity(tx.inputs.len());
        let mut input_sum: u64 = 0;
        let signing_msg = TxHash::signing_message_for_network(tx, &network);

        for input in &tx.inputs {
            let key = utxo_key(&input.txid, input.index)?;

            // [1] Duplicate inputs within same tx
            if !seen_inputs.insert(key) {
                return Err(StorageError::Other(format!(
                    "duplicate input {} in transaction {}",
                    key, tx.hash
                )));
            }

            // [2] Input UTXO must exist
            let utxo = utxo_set.get_utxo(&key).ok_or_else(|| {
                StorageError::KeyNotFound(format!("input utxo {} not found (tx {})", key, tx.hash))
            })?;

            // [3] Input UTXO must be unspent
            if utxo.spent {
                return Err(StorageError::Other(format!(
                    "input utxo {} already spent (tx {})",
                    key, tx.hash
                )));
            }

            // [NEW] Verify signature matches UTXO owner
            if !Self::verify_input_ownership(input, &utxo, &signing_msg) {
                return Err(StorageError::Other(format!(
                    "input {} signature does not match UTXO owner (tx {})",
                    key, tx.hash
                )));
            }

            // [5] Overflow protection
            input_sum = input_sum.checked_add(utxo.amount).ok_or_else(|| {
                StorageError::Other(format!(
                    "input sum overflow at utxo {} (tx {})",
                    key, tx.hash
                ))
            })?;
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
        let actual_fee = input_sum
            .checked_sub(output_sum)
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

        // (Confidential TXs returned earlier via the confidential gate; the
        // transparent path above does not apply to them.)
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
            Ok(b) if b.len() == PUBKEY_BYTES => match b.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            },
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
            Ok(b) if b.len() == SIGNATURE_BYTES => match b.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            },
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
    pub fn verify_input_ownership_by_address(
        input: &TxInput,
        owner_address: &str,
        signing_msg: &[u8],
    ) -> bool {
        if input.signature.is_empty() || input.pub_key.is_empty() {
            return false;
        }

        // Decode public key
        let pk_arr: [u8; 32] = match hex::decode(&input.pub_key) {
            Ok(b) if b.len() == PUBKEY_BYTES => match b.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            },
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
            Ok(b) if b.len() == SIGNATURE_BYTES => match b.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            },
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
    ///
    /// For transactions with 4+ inputs, verification runs in parallel via
    /// rayon. Below that threshold, the sequential path avoids thread-pool
    /// overhead. Each input's Ed25519 signature is verified independently
    /// against the transaction signing message.
    pub fn verify_signatures_for_network(tx: &Transaction, network: &NetworkMode) -> bool {
        if tx.inputs.is_empty() {
            return true;
        }

        let msg = TxHash::signing_message_for_network(tx, network);

        // Use parallel verification for transactions with many inputs (4+).
        // Below that threshold, rayon overhead exceeds the crypto work.
        if tx.inputs.len() >= 4 {
            use rayon::prelude::*;
            return tx.inputs.par_iter().all(|input| {
                Self::verify_single_input(input, &msg)
            });
        }

        // Sequential path for small transactions
        tx.inputs.iter().all(|input| {
            Self::verify_single_input(input, &msg)
        })
    }

    /// Verify a single input's Ed25519 signature against the signing message.
    ///
    /// Includes explicit public key validation:
    /// - Rejects all-zero (identity) public keys
    /// - Rejects known low-order points (small-subgroup attacks)
    /// - ed25519-dalek::VerifyingKey::from_bytes validates on-curve
    fn verify_single_input(input: &TxInput, msg: &[u8]) -> bool {
        if input.signature.is_empty() || input.pub_key.is_empty() {
            return false;
        }

        let sig_bytes: [u8; 64] = match hex::decode(&input.signature) {
            Ok(b) if b.len() == SIGNATURE_BYTES => match b.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            },
            _ => return false,
        };

        if !Self::s_is_canonical(&sig_bytes[32..]) {
            return false;
        }

        let pk_arr: [u8; 32] = match hex::decode(&input.pub_key) {
            Ok(b) if b.len() == PUBKEY_BYTES => match b.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            },
            _ => return false,
        };

        // Reject identity point (all zeros) — allows trivial signature forgery
        if pk_arr == [0u8; 32] {
            return false;
        }

        // Reject known Ed25519 low-order points (small-subgroup attacks).
        // These 8 points have order dividing the cofactor (8) and can be
        // used to forge signatures in non-cofactored verification.
        const LOW_ORDER_POINTS: [[u8; 32]; 5] = [
            [0; 32], // identity (already checked above)
            // (0, 1) — the neutral element in extended coordinates
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            // (0, -1) — point of order 2
            [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
            // Non-canonical encodings of identity
            [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ];
        if LOW_ORDER_POINTS.contains(&pk_arr) {
            return false;
        }

        // from_bytes validates on-curve (rejects non-curve points)
        let verifying_key = match VerifyingKey::from_bytes(&pk_arr) {
            Ok(k) => k,
            Err(_) => return false,
        };

        let signature = Signature::from_bytes(&sig_bytes);
        verifying_key.verify(msg, &signature).is_ok()
    }

    pub fn build_signing_message(tx: &Transaction) -> Vec<u8> {
        TxHash::signing_message(tx)
    }

    pub fn build_signing_message_for_network(tx: &Transaction, network: &NetworkMode) -> Vec<u8> {
        TxHash::signing_message_for_network(tx, network)
    }

    /// Validate TX timestamp is within acceptable range of current time.
    /// Rejects TXs older than MAX_TX_AGE_MS or more than MAX_TX_FUTURE_MS
    /// in the future (all MILLISECONDS). Coinbase TXs are exempt (their
    /// timestamp comes from the block header which has its own validation).
    pub fn validate_tx_timestamp(tx: &Transaction) -> Result<(), ConsensusError> {
        if tx.is_coinbase() {
            return Ok(());
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if tx.timestamp > now + MAX_TX_FUTURE_MS {
            return Err(ConsensusError::Timestamp(format!(
                "tx timestamp {} is {}ms in the future (max {}ms)",
                tx.timestamp,
                tx.timestamp - now,
                MAX_TX_FUTURE_MS
            )));
        }

        if now > tx.timestamp && (now - tx.timestamp) > MAX_TX_AGE_MS {
            return Err(ConsensusError::Timestamp(format!(
                "tx timestamp {} is {}ms old (max {}ms)",
                tx.timestamp,
                now - tx.timestamp,
                MAX_TX_AGE_MS
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
                    ph.len(),
                    PAYLOAD_HASH_HEX_LEN
                )));
            }
            if !ph.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(ConsensusError::BlockValidation(
                    "payload_hash contains non-hex characters".into(),
                ));
            }
            if ph.chars().any(|c| c.is_ascii_uppercase()) {
                return Err(ConsensusError::BlockValidation(
                    "payload_hash must use lowercase hex".into(),
                ));
            }
        }
        Ok(())
    }

    /// Check that S < L (Ed25519 group order).
    /// Ed25519 scalars are little-endian, so we compare from byte 31 (MSB) down to byte 0 (LSB).
    pub fn s_is_canonical(s_bytes: &[u8]) -> bool {
        if s_bytes.len() < 32 {
            return false;
        }

        // Compare from MSB (byte 31) to LSB (byte 0) for little-endian scalar
        for i in (0..32).rev() {
            if s_bytes[i] < ED25519_L[i] {
                return true;
            }
            if s_bytes[i] > ED25519_L[i] {
                return false;
            }
        }
        false // Equal to L is not canonical
    }

    fn validate_outputs_only(tx: &Transaction) -> bool {
        Self::sum_outputs(tx).is_some()
    }

    fn sum_outputs(tx: &Transaction) -> Option<u64> {
        let mut total: u64 = 0;

        for output in &tx.outputs {
            if output.amount < DUST_LIMIT {
                return None;
            }
            if output.amount > MAX_OUTPUT_AMOUNT {
                return None;
            }

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
            None => {
                return Err(ConsensusError::BlockValidation(
                    "SwapTx requires payload_hash".into(),
                ))
            }
        };
        if hash.len() != 64 {
            return Err(ConsensusError::BlockValidation(format!(
                "SwapTx payload_hash length {} != 64",
                hash.len()
            )));
        }
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ConsensusError::BlockValidation(
                "SwapTx payload_hash contains non-hex chars".into(),
            ));
        }
        if hash.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(ConsensusError::BlockValidation(
                "SwapTx payload_hash must use lowercase hex".into(),
            ));
        }
        if hash == &"0".repeat(64) {
            return Err(ConsensusError::BlockValidation(
                "SwapTx payload_hash must be non-zero".into(),
            ));
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
            None => {
                return Err(ConsensusError::BlockValidation(
                    "DexOrder requires payload_hash".into(),
                ))
            }
        };
        if data.is_empty() {
            return Err(ConsensusError::BlockValidation(
                "DexOrder payload_hash is empty".into(),
            ));
        }
        if data.len() != 64 {
            return Err(ConsensusError::BlockValidation(format!(
                "DexOrder payload_hash length {} != 64",
                data.len()
            )));
        }
        if !data.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ConsensusError::BlockValidation(
                "DexOrder payload_hash contains non-hex chars".into(),
            ));
        }
        if data.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(ConsensusError::BlockValidation(
                "DexOrder payload_hash must use lowercase hex".into(),
            ));
        }
        if data == &"0".repeat(64) {
            return Err(ConsensusError::BlockValidation(
                "DexOrder payload_hash must be non-zero".into(),
            ));
        }
        Ok(())
    }

    /// Validate ContractCreate transaction payload fields using network-specific
    /// contract address prefixes.
    pub fn validate_contract_create_payload_for_network(
        tx: &Transaction,
        network: &NetworkMode,
    ) -> Result<(), ConsensusError> {
        if tx.tx_type != TxType::ContractCreate {
            return Ok(()); // Not a contract create, skip
        }

        // gas_limit is required and must be > 0
        match tx.gas_limit {
            Some(gl) if gl > 0 => {}
            Some(_) => {
                return Err(ConsensusError::BlockValidation(
                    "contract create requires gas_limit > 0".into(),
                ))
            }
            None => {
                return Err(ConsensusError::BlockValidation(
                    "contract create requires gas_limit".into(),
                ))
            }
        }

        // vm_version must be Some(1) for v1 chain
        match tx.vm_version {
            Some(1) => {}
            Some(v) => {
                return Err(ConsensusError::BlockValidation(format!(
                    "contract create vm_version {} unsupported (expected 1)",
                    v
                )))
            }
            None => {
                return Err(ConsensusError::BlockValidation(
                    "contract create requires vm_version".into(),
                ))
            }
        }

        // deploy_code is required and must be non-empty
        match &tx.deploy_code {
            Some(code) if !code.is_empty() => {}
            Some(_) => {
                return Err(ConsensusError::BlockValidation(
                    "contract create requires non-empty deploy_code".into(),
                ))
            }
            None => {
                // Fall back to legacy payload_hash for backward compatibility
                let ph = match &tx.payload_hash {
                    Some(h) => h,
                    None => {
                        return Err(ConsensusError::BlockValidation(
                            "contract create requires deploy_code or bytecode payload".into(),
                        ))
                    }
                };
                if ph.is_empty() || ph == &"0".repeat(64) {
                    return Err(ConsensusError::BlockValidation(
                        "contract create requires non-zero bytecode payload".into(),
                    ));
                }
            }
        }

        // If contract address is precomputed/off-chain supplied, enforce network prefix.
        if let Some(addr) = &tx.contract_address {
            let expected = Self::contract_prefix_for_network(network);
            if !addr.starts_with(expected) {
                return Err(ConsensusError::BlockValidation(format!(
                    "contract create address {} must start with {}",
                    addr, expected
                )));
            }
        }

        Ok(())
    }

    /// Validate ContractCreate transaction payload fields.
    /// Requires deploy_code, gas_limit, and vm_version.
    /// Falls back to payload_hash for legacy support.
    pub fn validate_contract_create_payload(tx: &Transaction) -> Result<(), ConsensusError> {
        Self::validate_contract_create_payload_for_network(tx, &NetworkMode::Mainnet)
    }

    /// Validate ContractCall transaction payload fields using network-specific
    /// contract address prefixes.
    pub fn validate_contract_call_payload_for_network(
        tx: &Transaction,
        network: &NetworkMode,
    ) -> Result<(), ConsensusError> {
        if tx.tx_type != TxType::ContractCall {
            return Ok(()); // Not a contract call, skip
        }

        // gas_limit is required and must be > 0
        match tx.gas_limit {
            Some(gl) if gl > 0 => {}
            Some(_) => {
                return Err(ConsensusError::BlockValidation(
                    "contract call requires gas_limit > 0".into(),
                ))
            }
            None => {
                return Err(ConsensusError::BlockValidation(
                    "contract call requires gas_limit".into(),
                ))
            }
        }

        // vm_version must be Some(1) for v1 chain
        match tx.vm_version {
            Some(1) => {}
            Some(v) => {
                return Err(ConsensusError::BlockValidation(format!(
                    "contract call vm_version {} unsupported (expected 1)",
                    v
                )))
            }
            None => {
                return Err(ConsensusError::BlockValidation(
                    "contract call requires vm_version".into(),
                ))
            }
        }

        let expected_prefix = Self::contract_prefix_for_network(network);

        // contract_address is required and must have network-correct contract prefix
        match &tx.contract_address {
            Some(addr) if addr.starts_with(expected_prefix) => {}
            Some(addr) => {
                return Err(ConsensusError::BlockValidation(format!(
                    "contract call target {} must start with {}",
                    addr, expected_prefix
                )))
            }
            None => {
                // Fall back to legacy first-output check
                if let Some(output) = tx.outputs.first() {
                    if !output.address.starts_with(expected_prefix) {
                        return Err(ConsensusError::BlockValidation(format!(
                            "contract call target must be {} address",
                            expected_prefix
                        )));
                    }
                }
                // Also require legacy payload_hash
                let ph = match &tx.payload_hash {
                    Some(h) => h,
                    None => {
                        return Err(ConsensusError::BlockValidation(
                            "contract call requires calldata or contract_address".into(),
                        ))
                    }
                };
                if ph.is_empty() || ph == &"0".repeat(64) {
                    return Err(ConsensusError::BlockValidation(
                        "contract call requires non-zero calldata payload".into(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Validate ContractCall transaction payload fields.
    /// Requires contract_address (SD1c prefix), gas_limit, and vm_version.
    /// Falls back to payload_hash and first output for legacy support.
pub fn validate_contract_call_payload(tx: &Transaction) -> Result<(), ConsensusError> {
        Self::validate_contract_call_payload_for_network(tx, &NetworkMode::Mainnet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxOutput, TxType};
    use crate::domain::transaction::tx_hash::TxHash;

    fn make_contract_call(addr: &str) -> Transaction {
        let mut tx = Transaction::new(
            "ab".repeat(32),
            vec![],
            vec![TxOutput::new("SD1dest".into(), 1_000)],
            1,
            1_700_000_000,
        );
        tx.tx_type = TxType::ContractCall;
        tx.contract_address = Some(addr.to_string());
        tx.gas_limit = Some(21_000);
        tx.vm_version = Some(1);
        tx
    }

    #[test]
    fn contract_call_prefix_rejects_mainnet_addr_on_testnet() {
        let tx = make_contract_call("SD1c1234567890abcdef1234567890abcdef123456");
        let err = TxValidator::validate_contract_call_payload_for_network(
            &tx,
            &NetworkMode::Testnet,
        )
        .unwrap_err();
        assert!(err.to_string().contains("ST1c"), "{}", err);
    }

    #[test]
    fn contract_call_prefix_accepts_testnet_addr_on_testnet() {
        let tx = make_contract_call("ST1c1234567890abcdef1234567890abcdef123456");
        assert!(TxValidator::validate_contract_call_payload_for_network(&tx, &NetworkMode::Testnet)
            .is_ok());
    }

    #[test]
    fn structure_validation_rejects_mixed_network_output_prefixes() {
        let mut tx = Transaction::new_coinbase(
            "placeholder".into(),
            vec![
                TxOutput::new("SD1mine0000000000000000000000000000000001".into(), 1_000),
                TxOutput::new("ST1mine0000000000000000000000000000000002".into(), 1_000),
            ],
            0,
            1_700_000_000,
        );
        tx.hash = TxHash::hash_for_network(&tx, &NetworkMode::Mainnet);
        assert!(!TxValidator::validate_structure_for_network(
            &tx,
            &NetworkMode::Mainnet
        ));
    }

    #[test]
    fn structure_validation_accepts_consistent_network_output_prefixes() {
        let mut tx = Transaction::new_coinbase(
            "placeholder".into(),
            vec![
                TxOutput::new("SD1mine0000000000000000000000000000000001".into(), 1_000),
                TxOutput::new("SD1mine0000000000000000000000000000000002".into(), 1_000),
            ],
            0,
            1_700_000_001,
        );
        tx.hash = TxHash::hash_for_network(&tx, &NetworkMode::Mainnet);
        assert!(TxValidator::validate_structure_for_network(
            &tx,
            &NetworkMode::Mainnet
        ));
    }

    #[test]
    fn dex_order_payload_rejects_non_64_len_hash() {
        let mut tx = Transaction::new(
            "ab".repeat(32),
            vec![],
            vec![TxOutput::new("SD1dest".into(), 1_000)],
            1,
            1_700_000_000,
        );
        tx.tx_type = TxType::DexOrder;
        tx.payload_hash = Some("a".repeat(63));

        let err = TxValidator::validate_dex_order_payload(&tx).unwrap_err();
        assert!(
            err.to_string().contains("length 63 != 64"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn dex_order_payload_accepts_64_len_lower_hex_hash() {
        let mut tx = Transaction::new(
            "ab".repeat(32),
            vec![],
            vec![TxOutput::new("SD1dest".into(), 1_000)],
            1,
            1_700_000_001,
        );
        tx.tx_type = TxType::DexOrder;
        tx.payload_hash = Some("a".repeat(64));

        assert!(TxValidator::validate_dex_order_payload(&tx).is_ok());
    }

    #[test]
    fn swap_payload_rejects_zero_hash() {
        let mut tx = Transaction::new(
            "ab".repeat(32),
            vec![],
            vec![TxOutput::new("SD1hdeadbeef".into(), 1_000)],
            1,
            1_700_000_002,
        );
        tx.tx_type = TxType::SwapTx;
        tx.payload_hash = Some("0".repeat(64));

        let err = TxValidator::validate_swap_payload(&tx).unwrap_err();
        assert!(
            err.to_string().contains("must be non-zero"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn dex_order_payload_rejects_zero_hash() {
        let mut tx = Transaction::new(
            "ab".repeat(32),
            vec![],
            vec![TxOutput::new("SD1dest".into(), 1_000)],
            1,
            1_700_000_003,
        );
        tx.tx_type = TxType::DexOrder;
        tx.payload_hash = Some("0".repeat(64));

        let err = TxValidator::validate_dex_order_payload(&tx).unwrap_err();
        assert!(
            err.to_string().contains("must be non-zero"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn validate_confidential_rejects_malformed_via_shared_gate() {
        // The mempool entry point delegates to verify_confidential_tx (same gate
        // as the block path). A confidential tx with no ring data is malformed
        // and must be rejected. (The valid-path battery lives in
        // engine::privacy::ringct::confidential_consensus.)
        use crate::config::node::node_config::NetworkMode;
        use crate::domain::utxo::utxo_set::UtxoSet;
        let set = UtxoSet::new_empty();
        let mut tx = Transaction::new(
            "d".repeat(64),
            vec![],
            vec![TxOutput::new("SD1s".into(), 1)],
            0,
            1_700_000_000,
        );
        tx.tx_type = TxType::Confidential;
        tx.inputs.push(crate::domain::transaction::transaction::TxInput::new(
            "0".repeat(64),
            0,
            "owner".into(),
            String::new(),
            String::new(),
        ));
        assert!(!TxValidator::validate_confidential(
            &tx,
            &set,
            &NetworkMode::Mainnet
        ));
    }
}
