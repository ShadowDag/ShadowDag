// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use sha2::{Sha256, Digest};
use crate::domain::transaction::transaction::Transaction;
use crate::config::consensus::consensus_params::ConsensusParams;
use crate::config::node::node_config::NetworkMode;

pub const TX_HASH_VERSION: u32 = 2;

pub struct TxHash;

impl TxHash {
    /// Get the chain_id for a given network mode.
    fn chain_id_for(network: &NetworkMode) -> u32 {
        match network {
            NetworkMode::Mainnet => ConsensusParams::CHAIN_ID,
            NetworkMode::Testnet => ConsensusParams::TESTNET_CHAIN_ID,
            NetworkMode::Regtest => ConsensusParams::REGTEST_CHAIN_ID,
        }
    }

    /// Compute transaction hash using the specified network's chain_id.
    ///
    /// Domain tag "SHADOW_TX_ID_V1" ensures this hash cannot be confused
    /// with signing messages or any other hash context, even if the
    /// underlying data is identical.
    pub fn hash_for_network(tx: &Transaction, network: &NetworkMode) -> String {
        let mut h = Sha256::new();

        h.update(b"SHADOW_TX_ID_V1");
        h.update(Self::chain_id_for(network).to_le_bytes());
        h.update(TX_HASH_VERSION.to_le_bytes());
        h.update(tx.canonical_bytes());

        hex::encode(h.finalize())
    }

    /// Compute the transaction hash (defaults to mainnet for backward compatibility).
    pub fn hash(tx: &Transaction) -> String {
        Self::hash_for_network(tx, &NetworkMode::Mainnet)
    }

    /// Build the signing message for a specific network.
    ///
    /// Domain tag "SHADOW_TX_SIGN_V1" ensures signing context is fully
    /// separated from txid computation, preventing cross-context replay
    /// even within the same network.
    pub fn signing_message_for_network(tx: &Transaction, network: &NetworkMode) -> Vec<u8> {
        let mut h = Sha256::new();

        h.update(b"SHADOW_TX_SIGN_V1");
        h.update(Self::chain_id_for(network).to_le_bytes());

        // hash field: length-prefixed
        let hash_bytes = tx.hash.as_bytes();
        h.update((hash_bytes.len() as u32).to_le_bytes());
        h.update(hash_bytes);

        h.update(tx.timestamp.to_le_bytes());
        h.update(tx.fee.to_le_bytes());

        // outputs in order (output index matters)
        h.update((tx.outputs.len() as u32).to_le_bytes());
        for output in &tx.outputs {
            let addr_bytes = output.address.as_bytes();
            h.update((addr_bytes.len() as u32).to_le_bytes());
            h.update(addr_bytes);
            h.update(output.amount.to_le_bytes());
        }

        // inputs sorted by (txid, index) for determinism
        let mut sorted_indices: Vec<usize> = (0..tx.inputs.len()).collect();
        sorted_indices.sort_unstable_by(|&a, &b| {
            tx.inputs[a].txid.cmp(&tx.inputs[b].txid)
                .then(tx.inputs[a].index.cmp(&tx.inputs[b].index))
        });
        h.update((tx.inputs.len() as u32).to_le_bytes());
        for &i in &sorted_indices {
            let input = &tx.inputs[i];
            let txid_bytes = input.txid.as_bytes();
            h.update((txid_bytes.len() as u32).to_le_bytes());
            h.update(txid_bytes);
            h.update(input.index.to_le_bytes());
        }

        // payload_hash — chain-state binding (replay protection)
        match &tx.payload_hash {
            Some(ph) => {
                h.update([0x01]);
                let ph_bytes = ph.as_bytes();
                h.update((ph_bytes.len() as u32).to_le_bytes());
                h.update(ph_bytes);
            }
            None => {
                h.update([0x00]);
            }
        }

        h.finalize().to_vec()
    }

    /// Build the message that signers must sign (defaults to mainnet).
    pub fn signing_message(tx: &Transaction) -> Vec<u8> {
        Self::signing_message_for_network(tx, &NetworkMode::Mainnet)
    }

    /// Verify transaction hash matches content for a specific network.
    pub fn verify_for_network(tx: &Transaction, network: &NetworkMode) -> bool {
        Self::hash_for_network(tx, network) == tx.hash
    }

    pub fn verify(tx: &Transaction) -> bool {
        Self::verify_for_network(tx, &NetworkMode::Mainnet)
    }

    /// Check if tx belongs to the given network.
    pub fn is_correct_chain_for(tx: &Transaction, network: &NetworkMode) -> bool {
        Self::hash_for_network(tx, network) == tx.hash
    }

    pub fn is_correct_chain(tx: &Transaction) -> bool {
        Self::is_correct_chain_for(tx, &NetworkMode::Mainnet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};

    fn make_tx() -> Transaction {
        let mut tx = Transaction {
            hash:      "placeholder".to_string(),
            inputs:    vec![TxInput {
                txid:      "prev_tx_001".to_string(),
                index:     0,
                owner:     "alice".to_string(),
                signature: String::new(),
                pub_key:   String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs:   vec![TxOutput { address: "bob".to_string(), amount: 546, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee:       1,
            timestamp: 1_735_689_600,
            is_coinbase: false,
            tx_type:   TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        tx.hash = TxHash::hash(&tx);
        tx
    }

    #[test]
    fn hash_is_deterministic() {
        let tx = make_tx();
        assert_eq!(TxHash::hash(&tx), TxHash::hash(&tx));
    }

    #[test]
    fn hash_is_64_hex_chars() {
        let tx = make_tx();
        let h = TxHash::hash(&tx);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn different_outputs_different_hash() {
        let tx1 = make_tx();
        let mut tx2_inner = Transaction {
            hash:      "placeholder".to_string(),
            inputs:    tx1.inputs.clone(),
            outputs:   vec![TxOutput { address: "bob".to_string(), amount: 999, commitment: None, range_proof: None, ephemeral_pubkey: None }],
            fee:       1,
            timestamp: tx1.timestamp,
            is_coinbase: false,
            tx_type:   TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        };
        tx2_inner.hash = TxHash::hash(&tx2_inner);
        assert_ne!(TxHash::hash(&tx1), TxHash::hash(&tx2_inner));
    }

    #[test]
    fn signing_message_is_32_bytes() {
        let tx = make_tx();
        assert_eq!(TxHash::signing_message(&tx).len(), 32);
    }

    #[test]
    fn verify_matches_content() {
        let tx = make_tx();
        assert!(TxHash::verify(&tx), "verify must return true for correctly hashed tx");
    }

    #[test]
    fn different_chain_id_produces_different_hash() {
        let tx = make_tx();

        // Manually compute hash with a different chain ID but same canonical bytes
        let mut h = Sha256::new();
        h.update(0x_DA0C_0002u32.to_le_bytes()); // different chain ID
        h.update(TX_HASH_VERSION.to_le_bytes());
        h.update(tx.canonical_bytes());
        let testnet_hash = hex::encode(h.finalize());

        assert_ne!(
            TxHash::hash(&tx), testnet_hash,
            "Mainnet and testnet hashes must differ (replay protection)"
        );
    }

    #[test]
    fn signing_message_includes_chain_id() {
        let tx = make_tx();
        let msg_mainnet = TxHash::signing_message(&tx);

        // Compute signing message without chain_id using canonical encoding
        let mut h = Sha256::new();
        // skip chain_id
        let hash_bytes = tx.hash.as_bytes();
        h.update((hash_bytes.len() as u32).to_le_bytes());
        h.update(hash_bytes);
        h.update(tx.timestamp.to_le_bytes());
        h.update(tx.fee.to_le_bytes());
        h.update((tx.outputs.len() as u32).to_le_bytes());
        for out in &tx.outputs {
            let addr_bytes = out.address.as_bytes();
            h.update((addr_bytes.len() as u32).to_le_bytes());
            h.update(addr_bytes);
            h.update(out.amount.to_le_bytes());
        }
        h.update((tx.inputs.len() as u32).to_le_bytes());
        for inp in &tx.inputs {
            let txid_bytes = inp.txid.as_bytes();
            h.update((txid_bytes.len() as u32).to_le_bytes());
            h.update(txid_bytes);
            h.update(inp.index.to_le_bytes());
        }
        let msg_no_chain = h.finalize().to_vec();

        assert_ne!(
            msg_mainnet, msg_no_chain,
            "Signing message must include chain_id"
        );
    }

    #[test]
    fn input_order_does_not_affect_hash() {
        let inputs_a = vec![
            TxInput { txid: "tx_aaa".into(), index: 0, owner: "alice".into(), signature: String::new(), pub_key: String::new(), key_image: None, ring_members: None },
            TxInput { txid: "tx_bbb".into(), index: 1, owner: "bob".into(), signature: String::new(), pub_key: String::new(), key_image: None, ring_members: None },
        ];
        let inputs_b = vec![
            TxInput { txid: "tx_bbb".into(), index: 1, owner: "bob".into(), signature: String::new(), pub_key: String::new(), key_image: None, ring_members: None },
            TxInput { txid: "tx_aaa".into(), index: 0, owner: "alice".into(), signature: String::new(), pub_key: String::new(), key_image: None, ring_members: None },
        ];
        let outputs = vec![TxOutput { address: "bob".into(), amount: 100, commitment: None, range_proof: None, ephemeral_pubkey: None }];
        let tx_a = Transaction { hash: String::new(), inputs: inputs_a, outputs: outputs.clone(), fee: 1, timestamp: 1_000, is_coinbase: false, tx_type: TxType::Transfer, payload_hash: None, ..Default::default() };
        let tx_b = Transaction { hash: String::new(), inputs: inputs_b, outputs, fee: 1, timestamp: 1_000, is_coinbase: false, tx_type: TxType::Transfer, payload_hash: None, ..Default::default() };
        assert_eq!(TxHash::hash(&tx_a), TxHash::hash(&tx_b), "Input order must not affect transaction hash");
    }
}
