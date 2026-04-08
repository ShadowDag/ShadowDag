// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;

use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
use crate::domain::transaction::tx_validator::TxValidator;
use crate::errors::CryptoError;

pub struct KeyPairHex {
    pub private_key_hex: String,
    pub public_key_hex:  String,
    pub address:         String,
}

/// Generate a keypair with a network-specific address prefix.
///   - "mainnet" → SD1...
///   - "testnet" → ST1...
///   - "regtest" → SR1...
pub fn generate_keypair_for_network(network: &str) -> KeyPairHex {
    let signing_key   = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    let sk_hex = hex::encode(signing_key.to_bytes());
    let pk_hex = hex::encode(verifying_key.to_bytes());

    let mut h = Sha256::new();
    h.update(b"ShadowDAG_Addr_v1");
    h.update(verifying_key.to_bytes());
    let hash = h.finalize();

    let prefix = match network {
        "testnet" => "ST1",
        "regtest" => "SR1",
        _         => "SD1",
    };
    let address = format!("{}{}", prefix, hex::encode(&hash[..20]));

    KeyPairHex { private_key_hex: sk_hex, public_key_hex: pk_hex, address }
}

/// Generate a keypair (defaults to mainnet for backward compatibility).
pub fn generate_keypair() -> KeyPairHex {
    generate_keypair_for_network("mainnet")
}

pub fn build_transaction(
    inputs_refs:     Vec<(String, u32, String)>,
    outputs:         Vec<(String, u64)>,
    fee:             u64,
    private_key_hex: &str,
    public_key_hex:  &str,
) -> Result<Transaction, CryptoError> {
    build_transaction_with_anchor(inputs_refs, outputs, fee, private_key_hex, public_key_hex, None)
}

/// Build a transaction with an optional chain-state anchor (payload_hash).
///
/// When `anchor_block_hash` is Some, the TX is cryptographically bound to
/// that block's existence in the DAG. This prevents replay after deep reorgs
/// that remove the anchor block. Wallets SHOULD pass a recent tip hash.
pub fn build_transaction_with_anchor(
    inputs_refs:       Vec<(String, u32, String)>,
    outputs:           Vec<(String, u64)>,
    fee:               u64,
    private_key_hex:   &str,
    public_key_hex:    &str,
    anchor_block_hash: Option<String>,
) -> Result<Transaction, CryptoError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let tx_outputs: Vec<TxOutput> = outputs.into_iter()
        .map(|(address, amount)| TxOutput { address, amount, commitment: None, range_proof: None, ephemeral_pubkey: None })
        .collect();

    let temp_hash = build_tx_hash_from_refs(&inputs_refs, &tx_outputs, fee, timestamp);

    let mut tx_inputs: Vec<TxInput> = inputs_refs.iter()
        .map(|(txid, index, owner)| TxInput {
            txid:      txid.clone(),
            index:     *index,
            owner:     owner.clone(),
            signature: String::new(),
            pub_key:   public_key_hex.to_string(),
            key_image: None,
            ring_members: None,
        })
        .collect();

    let temp_tx = Transaction {
        hash:      temp_hash.clone(),
        inputs:    tx_inputs.clone(),
        outputs:   tx_outputs.clone(),
        fee,
        timestamp,
        is_coinbase: false,
        tx_type: TxType::Transfer,
        payload_hash: anchor_block_hash.clone(),
    };

    let signing_msg = TxValidator::build_signing_message(&temp_tx);

    let sk_bytes: Vec<u8> = hex::decode(private_key_hex)
        .map_err(|e| CryptoError::InvalidKey(format!("invalid private key hex: {}", e)))?;
    let sk_arr: [u8; 32] = sk_bytes.try_into()
        .map_err(|_| CryptoError::InvalidKey("private key must be 32 bytes".to_string()))?;
    let signing_key = SigningKey::from_bytes(&sk_arr);
    let sig_hex     = hex::encode(signing_key.sign(&signing_msg).to_bytes());

    for input in tx_inputs.iter_mut() {
        input.signature = sig_hex.clone();
        input.pub_key   = public_key_hex.to_string();
    }

    let final_tx = Transaction {
        hash:    temp_hash,
        inputs:  tx_inputs,
        outputs: tx_outputs,
        fee,
        timestamp,
        is_coinbase: false,
        tx_type: TxType::Transfer,
        payload_hash: anchor_block_hash,
    };

    Ok(final_tx)
}

pub fn build_coinbase(
    miner_address: String,
    dev_address:   String,
    block_reward:  u64,
    miner_pct:     u64,
    timestamp:     u64,
) -> Transaction {
    build_coinbase_at_height(miner_address, dev_address, block_reward, miner_pct, timestamp, 0)
}

pub fn build_coinbase_at_height(
    miner_address: String,
    dev_address:   String,
    block_reward:  u64,
    miner_pct:     u64,
    timestamp:     u64,
    height:        u64,
) -> Transaction {
    let miner_reward = ((block_reward as u128 * miner_pct as u128) / 100) as u64;
    let dev_reward   = block_reward.checked_sub(miner_reward)
        .expect("miner_reward <= block_reward");
    debug_assert_eq!(miner_reward + dev_reward, block_reward);

    let mut h = Sha256::new();
    h.update(b"coinbase");
    h.update(miner_address.as_bytes());
    h.update(timestamp.to_le_bytes());
    h.update(height.to_le_bytes());
    h.update(miner_reward.to_le_bytes());
    h.update(dev_reward.to_le_bytes());
    h.update(block_reward.to_le_bytes());
    let hash = hex::encode(h.finalize());

    Transaction::new_coinbase(
        hash,
        vec![
            TxOutput { address: miner_address, amount: miner_reward, commitment: None, range_proof: None, ephemeral_pubkey: None },
            TxOutput { address: dev_address,   amount: dev_reward, commitment: None, range_proof: None, ephemeral_pubkey: None },
        ],
        0,
        timestamp,
    )
}

pub fn build_tx_hash_from_refs(
    inputs:    &[(String, u32, String)],
    outputs:   &[TxOutput],
    fee:       u64,
    timestamp: u64,
) -> String {
    let mut h = Sha256::new();
    for (txid, index, _) in inputs {
        h.update(txid.as_bytes());
        h.update(index.to_le_bytes());
    }
    for output in outputs {
        h.update(output.address.as_bytes());
        h.update(output.amount.to_le_bytes());
    }
    h.update(fee.to_le_bytes());
    h.update(timestamp.to_le_bytes());
    hex::encode(h.finalize())
}

/// Build a batch of transactions efficiently.
/// Useful for exchanges, payment processors, and UTXO consolidation.
#[allow(clippy::type_complexity)]
pub fn build_batch_transactions(
    private_key_hex: &str,
    public_key_hex:  &str,
    batches: Vec<(Vec<(String, u32, String)>, Vec<(String, u64)>, u64)>,
) -> Vec<Result<Transaction, CryptoError>> {
    batches.into_iter().map(|(inputs, outputs, fee)| {
        build_transaction(inputs, outputs, fee, private_key_hex, public_key_hex)
    }).collect()
}

/// Build a UTXO consolidation transaction.
/// Merges many small UTXOs into a single output, reducing UTXO set bloat.
/// This is critical for long-term chain health (10+ years).
pub fn build_consolidation_tx(
    utxo_refs:       Vec<(String, u32, String)>,
    destination:     &str,
    fee:             u64,
    private_key_hex: &str,
    public_key_hex:  &str,
) -> Result<Transaction, CryptoError> {
    if utxo_refs.is_empty() {
        return Err(CryptoError::Other("No UTXOs to consolidate".into()));
    }
    // Single output = all value minus fee
    // Caller must calculate total value and subtract fee
    build_transaction(
        utxo_refs,
        vec![(destination.to_string(), 0)], // Amount filled by caller
        fee,
        private_key_hex,
        public_key_hex,
    )
}

/// Estimate the fee for a transaction based on its size.
pub fn estimate_tx_fee(input_count: usize, output_count: usize) -> u64 {
    use crate::config::consensus::consensus_params::ConsensusParams;
    // ~150 bytes per input + ~50 bytes per output + 50 bytes overhead
    let estimated_size = input_count * 150 + output_count * 50 + 50;
    let fee_per_byte = ConsensusParams::MIN_FEE;
    (estimated_size as u64) * fee_per_byte / 100
}

/// Maximum recommended inputs for a single consolidation TX
pub const MAX_CONSOLIDATION_INPUTS: usize = 500;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coinbase_hash_is_deterministic() {
        let tx1 = build_coinbase_at_height(
            "shadow1miner".to_string(),
            "shadow1dev".to_string(),
            10, 95, 1735689600, 1
        );
        let tx2 = build_coinbase_at_height(
            "shadow1miner".to_string(),
            "shadow1dev".to_string(),
            10, 95, 1735689600, 1
        );
        assert_eq!(tx1.hash, tx2.hash, "Coinbase hash must be deterministic");
    }

    #[test]
    fn coinbase_hash_differs_by_height() {
        let tx1 = build_coinbase_at_height(
            "shadow1miner".to_string(), "shadow1dev".to_string(), 10, 95, 1735689600, 1
        );
        let tx2 = build_coinbase_at_height(
            "shadow1miner".to_string(), "shadow1dev".to_string(), 10, 95, 1735689600, 2
        );
        assert_ne!(tx1.hash, tx2.hash);
    }

    #[test]
    fn keypair_generates_valid_address() {
        let kp = generate_keypair();
        assert!(kp.address.starts_with("SD1"), "Address must start with 'SD1'");
        assert_eq!(kp.public_key_hex.len(), 64, "Public key must be 32 bytes hex");
        assert_eq!(kp.private_key_hex.len(), 64, "Private key must be 32 bytes hex");
    }

    #[test]
    fn keypair_testnet_prefix() {
        let kp = generate_keypair_for_network("testnet");
        assert!(kp.address.starts_with("ST1"), "Testnet address must start with 'ST1'");
    }

    #[test]
    fn keypair_regtest_prefix() {
        let kp = generate_keypair_for_network("regtest");
        assert!(kp.address.starts_with("SR1"), "Regtest address must start with 'SR1'");
    }
}
