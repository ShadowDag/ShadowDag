// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::Transaction;
use crate::domain::utxo::utxo_set::{UtxoSet, utxo_key};
use crate::errors::StorageError;

/// Maximum allowed fee (prevents absurd fee attacks)
pub const MAX_FEE: u64 = 2_100_000_000_000_000_000; // 21 billion SDAG in satoshis

pub struct TxFee;

impl TxFee {
    /// Calculate fee from UTXO inputs vs outputs (safe from overflow)
    pub fn calculate_fee(tx: &Transaction, utxo_set: &UtxoSet) -> Result<u64, StorageError> {
        let mut input_sum: u64 = 0;
        let mut output_sum: u64 = 0;

        for input in &tx.inputs {
            let key = utxo_key(&input.txid, input.index)?;
            if let Some(utxo) = utxo_set.get_utxo(&key) {
                input_sum = input_sum.checked_add(utxo.amount)
                    .ok_or_else(|| StorageError::Other("Input sum overflow".to_string()))?;
            }
        }

        for output in &tx.outputs {
            output_sum = output_sum.checked_add(output.amount)
                .ok_or_else(|| StorageError::Other("Output sum overflow".to_string()))?;
        }

        if input_sum < output_sum {
            return Err(StorageError::Other(format!(
                "Outputs ({}) exceed inputs ({})", output_sum, input_sum
            )));
        }

        let fee = input_sum - output_sum;
        if fee > MAX_FEE {
            return Err(StorageError::Other(format!("Fee {} exceeds maximum {}", fee, MAX_FEE)));
        }

        Ok(fee)
    }

    /// Get the declared fee from the transaction
    pub fn calculate(tx: &Transaction) -> u64 {
        tx.fee
    }
}
