// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::block::block::Block;
use crate::domain::block::block_header::BlockHeader;
use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};

pub struct Serializer;

impl Serializer {
    // ─────────────────────────────────────────
    // PRIMITIVES (Vec)
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn write_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline(always)]
    pub fn write_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    #[inline(always)]
    pub fn write_str(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        assert!(
            bytes.len() <= u32::MAX as usize,
            "string length exceeds u32::MAX"
        );

        Self::write_u32(buf, bytes.len() as u32);
        buf.extend_from_slice(bytes);
    }

    // ─────────────────────────────────────────
    // PRIMITIVES (Hasher)
    // ─────────────────────────────────────────

    #[inline(always)]
    fn hash_u32(hasher: &mut impl sha2::Digest, v: u32) {
        hasher.update(v.to_le_bytes());
    }

    #[inline(always)]
    fn hash_u64(hasher: &mut impl sha2::Digest, v: u64) {
        hasher.update(v.to_le_bytes());
    }

    #[inline(always)]
    fn hash_str(hasher: &mut impl sha2::Digest, s: &str) {
        let bytes = s.as_bytes();
        Self::hash_u32(hasher, bytes.len() as u32);
        hasher.update(bytes);
    }

    // ─────────────────────────────────────────
    // TX INPUT / OUTPUT
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn serialize_tx_input(buf: &mut Vec<u8>, input: &TxInput) {
        Self::write_str(buf, &input.txid);
        Self::write_u32(buf, input.index);
        Self::write_str(buf, &input.owner);
        Self::write_str(buf, &input.pub_key);
        if let Some(ref ki) = input.key_image {
            buf.push(0x01);
            Self::write_str(buf, ki);
        } else {
            buf.push(0x00);
        }
    }

    #[inline(always)]
    pub fn serialize_tx_output(buf: &mut Vec<u8>, output: &TxOutput) {
        Self::write_str(buf, &output.address);
        Self::write_u64(buf, output.amount);
        if let Some(ref c) = output.commitment {
            buf.push(0x01);
            Self::write_str(buf, c);
        } else {
            buf.push(0x00);
        }
        if let Some(ref rp) = output.range_proof {
            buf.push(0x01);
            Self::write_str(buf, rp);
        } else {
            buf.push(0x00);
        }
        if let Some(ref epk) = output.ephemeral_pubkey {
            buf.push(0x01);
            Self::write_str(buf, epk);
        } else {
            buf.push(0x00);
        }
    }

    #[inline(always)]
    fn hash_tx_input(hasher: &mut impl sha2::Digest, input: &TxInput) {
        Self::hash_str(hasher, &input.txid);
        Self::hash_u32(hasher, input.index);
        Self::hash_str(hasher, &input.owner);
        Self::hash_str(hasher, &input.pub_key);
        if let Some(ref ki) = input.key_image {
            hasher.update([0x01]);
            Self::hash_str(hasher, ki);
        } else {
            hasher.update([0x00]);
        }
    }

    #[inline(always)]
    fn hash_tx_output(hasher: &mut impl sha2::Digest, output: &TxOutput) {
        Self::hash_str(hasher, &output.address);
        Self::hash_u64(hasher, output.amount);
        if let Some(ref c) = output.commitment {
            hasher.update([0x01]);
            Self::hash_str(hasher, c);
        } else {
            hasher.update([0x00]);
        }
        if let Some(ref rp) = output.range_proof {
            hasher.update([0x01]);
            Self::hash_str(hasher, rp);
        } else {
            hasher.update([0x00]);
        }
        if let Some(ref epk) = output.ephemeral_pubkey {
            hasher.update([0x01]);
            Self::hash_str(hasher, epk);
        } else {
            hasher.update([0x00]);
        }
    }

    // ─────────────────────────────────────────
    // TRANSACTION
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + tx.inputs.len() * 64 + tx.outputs.len() * 64);

        Self::serialize_transaction_into(&mut buf, tx);
        buf
    }

    #[inline(always)]
    fn sorted_input_indices(inputs: &[TxInput]) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..inputs.len()).collect();
        idx.sort_unstable_by(|&a, &b| {
            inputs[a]
                .txid
                .cmp(&inputs[b].txid)
                .then(inputs[a].index.cmp(&inputs[b].index))
        });
        idx
    }

    #[inline(always)]
    fn tx_type_byte(tx_type: &TxType) -> u8 {
        match tx_type {
            TxType::Transfer => 0x00,
            TxType::Confidential => 0x01,
            TxType::ContractCreate => 0x02,
            TxType::ContractCall => 0x03,
            TxType::AtomicSwap => 0x04,
            TxType::MultiSig => 0x05,
            TxType::TokenTransfer => 0x06,
            TxType::SwapTx => 0x07,
            TxType::DexOrder => 0x08,
        }
    }

    #[inline(always)]
    pub fn serialize_transaction_into(buf: &mut Vec<u8>, tx: &Transaction) {
        Self::write_u32(buf, 2);
        Self::write_u64(buf, tx.timestamp);
        Self::write_u64(buf, tx.fee);

        // tx_type discriminant
        buf.push(Self::tx_type_byte(&tx.tx_type));
        // is_coinbase flag
        buf.push(if tx.is_coinbase { 0x01 } else { 0x00 });
        // payload_hash if present
        if let Some(ref ph) = tx.payload_hash {
            buf.push(0x01);
            Self::write_str(buf, ph);
        } else {
            buf.push(0x00);
        }

        let sorted = Self::sorted_input_indices(&tx.inputs);
        Self::write_u32(buf, tx.inputs.len() as u32);
        for &i in &sorted {
            Self::serialize_tx_input(buf, &tx.inputs[i]);
        }

        Self::write_u32(buf, tx.outputs.len() as u32);
        for out in &tx.outputs {
            Self::serialize_tx_output(buf, out);
        }
    }

    // ─────────────────────────────────────────
    // BLOCK HEADER (🔥 بدون clone)
    // ─────────────────────────────────────────

    #[inline(always)]
    fn sorted_parent_indices(parents: &[String]) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..parents.len()).collect();
        idx.sort_unstable_by(|&a, &b| parents[a].cmp(&parents[b]));
        idx
    }

    #[inline(always)]
    pub fn serialize_block_header(header: &BlockHeader) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        Self::serialize_block_header_into(&mut buf, header);
        buf
    }

    #[inline(always)]
    pub fn serialize_block_header_into(buf: &mut Vec<u8>, header: &BlockHeader) {
        Self::write_u32(buf, header.version);
        Self::write_u64(buf, header.height);
        Self::write_u64(buf, header.timestamp);
        Self::write_u64(buf, header.nonce);
        Self::write_u64(buf, header.difficulty);

        Self::write_str(buf, &header.merkle_root);

        let idx = Self::sorted_parent_indices(&header.parents);

        Self::write_u32(buf, idx.len() as u32);
        for i in idx {
            Self::write_str(buf, &header.parents[i]);
        }

        Self::write_u64(buf, header.blue_score);

        match &header.selected_parent {
            None => buf.push(0),
            Some(sp) => {
                buf.push(1);
                Self::write_str(buf, sp);
            }
        }

        Self::write_u64(buf, header.extra_nonce);
        if let Some(ref uc) = header.utxo_commitment {
            buf.push(0x01);
            Self::write_str(buf, uc);
        } else {
            buf.push(0x00);
        }
    }

    // ─────────────────────────────────────────
    // BLOCK
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn serialize_block(block: &Block) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);

        Self::serialize_block_header_into(&mut buf, &block.header);

        let txs = &block.body.transactions;
        Self::write_u32(&mut buf, txs.len() as u32);

        for tx in txs {
            let start = buf.len();
            buf.extend_from_slice(&[0u8; 4]);

            let before = buf.len();
            Self::serialize_transaction_into(&mut buf, tx);
            let size = (buf.len() - before) as u32;

            buf[start..start + 4].copy_from_slice(&size.to_le_bytes());
        }

        buf
    }

    // ─────────────────────────────────────────
    // HASHING (🔥 ZERO COPY + NO CLONE)
    // ─────────────────────────────────────────

    #[inline(always)]
    pub fn tx_hash(tx: &Transaction) -> String {
        use sha2::{Digest, Sha256};

        let mut h = Sha256::new();

        Self::hash_u32(&mut h, 2);
        Self::hash_u64(&mut h, tx.timestamp);
        Self::hash_u64(&mut h, tx.fee);

        // tx_type discriminant
        h.update([Self::tx_type_byte(&tx.tx_type)]);
        // is_coinbase flag
        h.update([if tx.is_coinbase { 0x01 } else { 0x00 }]);
        // payload_hash if present
        if let Some(ref ph) = tx.payload_hash {
            h.update([0x01]);
            Self::hash_str(&mut h, ph);
        } else {
            h.update([0x00]);
        }

        let sorted = Self::sorted_input_indices(&tx.inputs);
        Self::hash_u32(&mut h, tx.inputs.len() as u32);
        for &i in &sorted {
            Self::hash_tx_input(&mut h, &tx.inputs[i]);
        }

        Self::hash_u32(&mut h, tx.outputs.len() as u32);
        for out in &tx.outputs {
            Self::hash_tx_output(&mut h, out);
        }

        hex::encode(h.finalize())
    }

    #[inline(always)]
    pub fn block_header_hash(header: &BlockHeader) -> String {
        use sha2::{Digest, Sha256};

        let mut h = Sha256::new();

        Self::hash_u32(&mut h, header.version);
        Self::hash_u64(&mut h, header.height);
        Self::hash_u64(&mut h, header.timestamp);
        Self::hash_u64(&mut h, header.nonce);
        Self::hash_u64(&mut h, header.difficulty);

        Self::hash_str(&mut h, &header.merkle_root);

        let idx = Self::sorted_parent_indices(&header.parents);

        Self::hash_u32(&mut h, idx.len() as u32);
        for i in idx {
            Self::hash_str(&mut h, &header.parents[i]);
        }

        Self::hash_u64(&mut h, header.blue_score);

        match &header.selected_parent {
            None => h.update([0]),
            Some(sp) => {
                h.update([1]);
                Self::hash_str(&mut h, sp);
            }
        }

        Self::hash_u64(&mut h, header.extra_nonce);
        if let Some(ref uc) = header.utxo_commitment {
            h.update([0x01]);
            Self::hash_str(&mut h, uc);
        } else {
            h.update([0x00]);
        }

        hex::encode(h.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::block::block_header::BlockHeader;
    use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};

    fn make_tx() -> Transaction {
        Transaction {
            hash: String::new(),
            inputs: vec![TxInput {
                txid: "abc".to_string(),
                index: 0,
                owner: "alice".to_string(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
            }],
            outputs: vec![TxOutput {
                address: "bob".to_string(),
                amount: 900,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            }],
            fee: 100,
            timestamp: 1_000_000,
            is_coinbase: false,
            tx_type: TxType::Transfer,
            payload_hash: None,
            ..Default::default()
        }
    }

    fn make_header() -> BlockHeader {
        BlockHeader {
            version: 1,
            hash: String::new(),
            parents: vec!["p1".to_string(), "p2".to_string()],
            merkle_root: "mr".to_string(),
            timestamp: 999,
            nonce: 42,
            difficulty: 1000,
            height: 5,
            blue_score: 3,
            selected_parent: Some("p1".to_string()),
            utxo_commitment: None,
            extra_nonce: 0,
            receipt_root: None,
            state_root: None,
        }
    }

    #[test]
    fn tx_serialization_is_deterministic() {
        let tx = make_tx();
        let b1 = Serializer::serialize_transaction(&tx);
        let b2 = Serializer::serialize_transaction(&tx);
        assert_eq!(b1, b2);
    }

    #[test]
    fn tx_hash_is_deterministic() {
        let tx = make_tx();
        let h1 = Serializer::tx_hash(&tx);
        let h2 = Serializer::tx_hash(&tx);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn different_txs_different_hashes() {
        let tx1 = make_tx();
        let mut tx2 = make_tx();
        tx2.fee = 200;
        let h1 = Serializer::tx_hash(&tx1);
        let h2 = Serializer::tx_hash(&tx2);
        assert_ne!(h1, h2);
    }

    #[test]
    fn header_serialization_is_deterministic() {
        let h = make_header();
        let b1 = Serializer::serialize_block_header(&h);
        let b2 = Serializer::serialize_block_header(&h);
        assert_eq!(b1, b2);
    }

    #[test]
    fn header_parents_sorted_for_determinism() {
        let h1 = make_header();
        let mut h2 = make_header();
        h2.parents = vec!["p2".to_string(), "p1".to_string()];
        let b1 = Serializer::serialize_block_header(&h1);
        let b2 = Serializer::serialize_block_header(&h2);
        assert_eq!(b1, b2, "parent order must not affect hash");
    }

    #[test]
    fn block_header_hash_hex_length() {
        let h = make_header();
        let hash = Serializer::block_header_hash(&h);
        assert_eq!(hash.len(), 64);
    }
}
