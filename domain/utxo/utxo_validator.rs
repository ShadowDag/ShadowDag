// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block::Block;
use crate::config::node::node_config::NetworkMode;
use crate::domain::transaction::transaction::Transaction;
use crate::domain::transaction::tx_hash::TxHash;
use crate::domain::transaction::tx_validator::TxValidator;
use crate::domain::utxo::utxo_key::UtxoKey;
use crate::domain::utxo::utxo_set::{utxo_key, UtxoSet};
use crate::errors::StorageError;
use std::collections::{HashMap, HashSet};

/// Best-effort network inference from a block's output address prefixes
/// (ST1*=Testnet, SR1*=Regtest, else Mainnet). Used only to pick the chain_id
/// for the confidential signing message. Proper threading of the node's network
/// is audit follow-up H-net.
fn infer_block_network(block: &Block) -> NetworkMode {
    for tx in &block.body.transactions {
        for o in &tx.outputs {
            if o.address.starts_with("ST1") {
                return NetworkMode::Testnet;
            }
            if o.address.starts_with("SR1") {
                return NetworkMode::Regtest;
            }
            if o.address.starts_with("SD1") {
                return NetworkMode::Mainnet;
            }
        }
    }
    NetworkMode::Mainnet
}

pub struct UtxoValidator;

impl UtxoValidator {
    #[inline]
    fn network_from_owner_address(owner_address: &str) -> NetworkMode {
        if owner_address.starts_with("ST1") {
            NetworkMode::Testnet
        } else if owner_address.starts_with("SR1") {
            NetworkMode::Regtest
        } else {
            // Keep backward compatibility for legacy/plain owners used in tests.
            NetworkMode::Mainnet
        }
    }

    pub fn validate(tx: &Transaction, utxo_set: &UtxoSet) -> bool {
        // Non-coinbase tx MUST have inputs. Empty inputs = reject.
        // Coinbase tx are validated separately (they have no inputs by design).
        if tx.inputs.is_empty() {
            return tx.is_coinbase();
        }

        let mut seen: HashSet<UtxoKey> = HashSet::new();

        for input in &tx.inputs {
            let key = match utxo_key(&input.txid, input.index) {
                Ok(k) => k,
                Err(_) => return false,
            };

            if seen.contains(&key) {
                return false;
            }
            seen.insert(key);

            let utxo = match utxo_set.get_utxo(&key) {
                Some(u) => u,
                None => {
                    return false;
                }
            };

            if utxo.spent {
                return false;
            }

            // SECURITY: Both UTXO and input MUST have an owner, and they MUST match
            if utxo.owner.is_empty() {
                return false; // UTXO without owner is invalid
            }
            if input.owner.is_empty() {
                return false; // Input must declare the owner
            }
            if utxo.owner != input.owner {
                return false; // Owner mismatch — unauthorized spend attempt
            }
        }

        true
    }

    pub fn sum_inputs(tx: &Transaction, utxo_set: &UtxoSet) -> Option<u64> {
        if tx.inputs.is_empty() {
            return Some(0);
        }
        let mut total: u64 = 0;
        for input in &tx.inputs {
            let key = utxo_key(&input.txid, input.index).ok()?;
            let utxo = utxo_set.get_utxo(&key)?;
            total = total.checked_add(utxo.amount)?;
        }
        Some(total)
    }

    /// Unified UTXO validation for an entire block.
    ///
    /// Validates all transactions against the UTXO set:
    ///   - Empty outputs check (all tx including coinbase)
    ///   - Coinbase must have 0 inputs; non-coinbase must have >= 1
    ///   - Coinbase output overflow protection
    ///   - Duplicate inputs within same tx
    ///   - Cross-tx double-spend within block
    ///   - Input UTXO existence and unspent status
    ///   - Signature verification against UTXO owner
    ///   - Input/output sum overflow protection
    ///   - inputs >= outputs
    ///   - Declared fee matches actual fee
    ///
    /// This is the single entry point for all UTXO validation logic.
    /// Validate all UTXO operations in a block, including intra-block spends.
    ///
    /// Supports the case where tx2 inside the same block spends an output
    /// created by tx1 earlier in the block, via `staged_outputs`.
    ///
    /// This is the SINGLE source of truth for block-level UTXO validation.
    pub fn validate_block_utxos(
        block: &Block,
        utxo_set: &UtxoSet,
        block_height: u64,
    ) -> Result<(), StorageError> {
        let transactions = &block.body.transactions;

        // Track which keys have been spent in this block (cross-tx double-spend)
        let mut will_spend: HashSet<UtxoKey> = HashSet::with_capacity(transactions.len() * 2);

        // Staged outputs: outputs created by earlier txs in THIS block,
        // available for spending by later txs in the same block.
        // Key: "txid:index" → (address, amount, is_coinbase)
        let mut staged_outputs: HashMap<UtxoKey, (String, u64, bool)> =
            HashMap::with_capacity(transactions.len() * 2);

        // RingCT: network for the confidential signing message + block-wide
        // key-image set for intra-block double-spend detection.
        let conf_network = infer_block_network(block);
        let mut seen_key_images: HashSet<String> = HashSet::new();

        for tx in transactions {
            // Empty outputs check (applies to all tx including coinbase)
            if tx.outputs.is_empty() {
                return Err(StorageError::Other(format!(
                    "validate_block_utxos: tx {} has no outputs",
                    tx.hash
                )));
            }

            // Coinbase must have 0 inputs; non-coinbase must have >= 1
            if tx.is_coinbase() {
                if !tx.inputs.is_empty() {
                    return Err(StorageError::Other(format!(
                        "validate_block_utxos: coinbase tx {} must have exactly 0 inputs",
                        tx.hash
                    )));
                }
                // Validate coinbase output amounts (overflow protection)
                let mut coinbase_total: u64 = 0;
                for (idx, output) in tx.outputs.iter().enumerate() {
                    coinbase_total =
                        coinbase_total.checked_add(output.amount).ok_or_else(|| {
                            StorageError::Other(format!(
                                "validate_block_utxos: coinbase output sum overflow (tx {})",
                                tx.hash
                            ))
                        })?;
                    // Stage coinbase outputs for potential intra-block spending
                    let key = utxo_key(&tx.hash, idx as u32)?;
                    staged_outputs.insert(key, (output.address.clone(), output.amount, true));
                }
                continue;
            }

            // RingCT confidential tx: verified entirely by the confidential gate
            // (CLSAG + ring authenticity + key images + range + homomorphic
            // balance). Confidential inputs do NOT spend transparent UTXOs and
            // confidential outputs are NOT staged into the transparent map.
            if tx.is_confidential() {
                crate::engine::privacy::ringct::confidential_consensus::verify_confidential_tx(
                    tx,
                    utxo_set,
                    &conf_network,
                    &mut seen_key_images,
                )?;
                continue;
            }

            // Non-coinbase must have inputs
            if tx.inputs.is_empty() {
                return Err(StorageError::Other(format!(
                    "validate_block_utxos: non-coinbase tx {} has no inputs",
                    tx.hash
                )));
            }

            // Duplicate inputs within same tx + UTXO checks
            let mut seen_in_tx: HashSet<UtxoKey> = HashSet::with_capacity(tx.inputs.len());
            let mut input_sum: u64 = 0;
            let mut tx_network: Option<NetworkMode> = None;
            let mut signing_msg: Option<Vec<u8>> = None;

            for input in &tx.inputs {
                let key = utxo_key(&input.txid, input.index)?;

                // Duplicate input within same transaction
                if !seen_in_tx.insert(key) {
                    return Err(StorageError::Other(format!(
                        "validate_block_utxos: duplicate input {} within tx {}",
                        key, tx.hash
                    )));
                }

                // Cross-tx double-spend within block
                if will_spend.contains(&key) {
                    return Err(StorageError::Other(format!(
                        "validate_block_utxos: double-spend within block: {} (tx {})",
                        key, tx.hash
                    )));
                }

                // Input must exist in base UTXO set OR in staged outputs from
                // earlier transactions in this same block.
                let (owner, amount, _is_staged_coinbase) = if let Some(utxo) =
                    utxo_set.get_utxo(&key)
                {
                    // Found in base UTXO set
                    if utxo.spent {
                        return Err(StorageError::Other(format!(
                            "validate_block_utxos: utxo {} already spent (tx {})",
                            key, tx.hash
                        )));
                    }

                    // Coinbase maturity check (base UTXO set only)
                    if let Some(created_height) = utxo_set.coinbase_created_height(&key) {
                        let confirmations = block_height.saturating_sub(created_height);
                        let maturity = utxo_set.coinbase_maturity();
                        if confirmations < maturity {
                            return Err(StorageError::Other(format!(
                                    "validate_block_utxos: coinbase utxo {} immature: {} confirmations < required {} (tx {})",
                                    key, confirmations, maturity, tx.hash
                                )));
                        }
                    }

                    (utxo.address.clone(), utxo.amount, false)
                } else if let Some((addr, amt, is_cb)) = staged_outputs.get(&key) {
                    // Found in staged outputs from earlier tx in this block
                    if *is_cb {
                        // Coinbase outputs created in THIS block cannot be spent
                        // in the same block — they need COINBASE_MATURITY confirmations
                        return Err(StorageError::Other(format!(
                                "validate_block_utxos: cannot spend coinbase output {} in same block (tx {})",
                                key, tx.hash
                            )));
                    }
                    (addr.clone(), *amt, false)
                } else {
                    return Err(StorageError::Other(format!(
                            "validate_block_utxos: utxo {} not found in UTXO set or earlier block txs (tx {})",
                            key, tx.hash
                        )));
                };

                // Determine tx network from input owners and enforce consistency
                // across all inputs in the same transaction.
                let input_network = Self::network_from_owner_address(&owner);
                match tx_network {
                    None => {
                        tx_network = Some(input_network.clone());
                        signing_msg = Some(TxHash::signing_message_for_network(tx, &input_network));
                    }
                    Some(ref net) if *net != input_network => {
                        return Err(StorageError::Other(format!(
                            "validate_block_utxos: mixed input networks in tx {}",
                            tx.hash
                        )));
                    }
                    _ => {}
                }

                // Verify signature matches UTXO owner.
                let msg = signing_msg
                    .as_ref()
                    .ok_or_else(|| StorageError::Other("missing signing message".into()))?;
                if !TxValidator::verify_input_ownership_by_address(input, &owner, msg) {
                    return Err(StorageError::Other(format!(
                        "validate_block_utxos: input {} signature does not match UTXO owner (tx {})",
                        key, tx.hash
                    )));
                }

                // Overflow protection on input sum
                input_sum = input_sum.checked_add(amount).ok_or_else(|| {
                    StorageError::Other(format!(
                        "validate_block_utxos: input sum overflow at {} (tx {})",
                        key, tx.hash
                    ))
                })?;

                will_spend.insert(key);
            }

            // Overflow-safe output sum
            let mut output_sum: u64 = 0;
            for output in &tx.outputs {
                output_sum = output_sum.checked_add(output.amount).ok_or_else(|| {
                    StorageError::Other(format!(
                        "validate_block_utxos: output sum overflow (tx {})",
                        tx.hash
                    ))
                })?;
            }

            // inputs >= outputs
            if input_sum < output_sum {
                return Err(StorageError::Other(format!(
                    "validate_block_utxos: inputs ({}) < outputs ({}) in tx {}",
                    input_sum, output_sum, tx.hash
                )));
            }

            // Fee consistency check
            let actual_fee = input_sum.checked_sub(output_sum).ok_or_else(|| {
                StorageError::Other(format!(
                    "validate_block_utxos: fee underflow in tx {}",
                    tx.hash
                ))
            })?;

            if actual_fee != tx.fee {
                return Err(StorageError::Other(format!(
                    "validate_block_utxos: declared fee ({}) != actual fee ({}) in tx {}",
                    tx.fee, actual_fee, tx.hash
                )));
            }

            // Stage this tx's outputs for potential spending by later txs
            for (idx, output) in tx.outputs.iter().enumerate() {
                let key = utxo_key(&tx.hash, idx as u32)?;
                staged_outputs.insert(key, (output.address.clone(), output.amount, false));
            }
        }

        Ok(())
    }
}
