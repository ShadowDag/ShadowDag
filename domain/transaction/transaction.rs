// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use serde::{Serialize, Deserialize};

/// Transaction type for VM routing. Transfer transactions go through the
/// UTXO layer; ContractCreate and ContractCall are executed through
/// ShadowVM v1 during block processing (see full_node.rs).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum TxType {
    #[default]
    Transfer,
    /// Privacy transaction — ring signatures + confidential amounts
    Confidential,
    ContractCreate,
    ContractCall,
    /// Atomic swap — hash time-locked contract for cross-chain trading
    AtomicSwap,
    /// Multi-signature transaction
    MultiSig,
    /// Token transfer (SRC-20 standard)
    TokenTransfer,
    /// Swap transaction — wraps an HTLC operation (initiate/redeem/refund)
    SwapTx,
    /// DEX order placement/cancellation transaction
    DexOrder,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxInput {
    pub txid:      String,
    pub index:     u32,
    pub owner:     String,
    pub signature: String,
    pub pub_key:   String,
    /// Key image for double-spend prevention in privacy transactions.
    /// Hex-encoded compressed Ristretto point. None for transparent TXs.
    #[serde(default)]
    pub key_image: Option<String>,
    /// Ring member public keys (hex) used in ring signature.
    /// None for transparent TXs.
    #[serde(default)]
    pub ring_members: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxOutput {
    pub address: String,
    pub amount:  u64,
    /// Pedersen commitment hiding the real amount (hex).
    /// None for transparent TXs — amount field is used directly.
    #[serde(default)]
    pub commitment: Option<String>,
    /// Bulletproof range proof bytes (hex).
    /// Proves commitment hides a value in [0, 2^64) without revealing it.
    #[serde(default)]
    pub range_proof: Option<String>,
    /// Ephemeral public key for stealth address scanning (hex-encoded compressed Ristretto).
    /// Present on stealth outputs so the recipient can perform ECDH to detect ownership.
    #[serde(default)]
    pub ephemeral_pubkey: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Transaction {
    pub hash:        String,
    pub inputs:      Vec<TxInput>,
    pub outputs:     Vec<TxOutput>,
    pub fee:         u64,
    pub timestamp:   u64,
    #[serde(default)]
    pub is_coinbase: bool,
    #[serde(default)]
    pub tx_type: TxType,
    /// Optional chain-state binding: hex-encoded hash of a recent block.
    /// When present, the TX is only valid if the referenced block exists
    /// in the DAG. This prevents replay after deep reorgs that remove the
    /// anchor block. Wallets SHOULD set this to a recent tip hash.
    /// None for backward compatibility with legacy TXs and coinbase.
    #[serde(default)]
    pub payload_hash: Option<String>,
    /// Gas limit for contract execution (ContractCreate/ContractCall only)
    #[serde(default)]
    pub gas_limit: Option<u64>,
    /// Contract bytecode for deployment (ContractCreate only)
    #[serde(default)]
    pub deploy_code: Option<Vec<u8>>,
    /// Calldata for contract invocation (ContractCall only)
    #[serde(default)]
    pub calldata: Option<Vec<u8>>,
    /// Target contract address (ContractCall only)
    #[serde(default)]
    pub contract_address: Option<String>,
    /// VM version this transaction targets (must match chain's active VM version)
    #[serde(default)]
    pub vm_version: Option<u8>,
}

impl Transaction {
    pub fn new(
        hash:      String,
        inputs:    Vec<TxInput>,
        outputs:   Vec<TxOutput>,
        fee:       u64,
        timestamp: u64,
    ) -> Self {
        Self {
            hash, inputs, outputs, fee, timestamp,
            is_coinbase: false, tx_type: TxType::Transfer, payload_hash: None,
            gas_limit: None, deploy_code: None, calldata: None,
            contract_address: None, vm_version: None,
        }
    }

    pub fn new_coinbase(
        hash:    String,
        outputs: Vec<TxOutput>,
        fee:     u64,
        timestamp: u64,
    ) -> Self {
        Self {
            hash, inputs: vec![], outputs, fee, timestamp,
            is_coinbase: true, tx_type: TxType::Transfer, payload_hash: None,
            gas_limit: None, deploy_code: None, calldata: None,
            contract_address: None, vm_version: None,
        }
    }

    pub fn is_coinbase(&self) -> bool {
        self.is_coinbase
    }

    /// Returns true if this is a privacy (confidential) transaction
    /// that requires ring signature and commitment verification.
    pub fn is_confidential(&self) -> bool {
        self.tx_type == TxType::Confidential
    }

    /// Sum of all output amounts. Returns None on overflow (attack detection).
    pub fn total_output_checked(&self) -> Option<u64> {
        let mut total: u64 = 0;
        for o in &self.outputs {
            total = total.checked_add(o.amount)?;
        }
        Some(total)
    }

    /// Sum of all output amounts. Panics on overflow — prefer total_output_checked().
    pub fn total_output(&self) -> u64 {
        self.total_output_checked()
            .expect("output sum overflow — malformed transaction")
    }

    /// Canonical serialization for transaction hashing (txid computation).
    ///
    /// IMPORTANT: Signatures are intentionally EXCLUDED from canonical_bytes
    /// to prevent circular hashing (signature signs the hash, hash includes
    /// the data). This is the same design as Bitcoin's SegWit: the txid
    /// commits to the transaction structure, and signatures are verified
    /// separately via signing_message().
    ///
    /// Fields are serialized in a fixed order. Integers use little-endian encoding.
    /// Strings are length-prefixed UTF-8 (u32 LE length + bytes).
    /// Vectors are length-prefixed sequences (u32 LE count + elements).
    /// Inputs are sorted by (txid, index) before encoding to ensure order-independence.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            8 + 8 + // fee + timestamp
            4 + self.inputs.len() * 48 +
            4 + self.outputs.len() * 48
        );

        // 1. tx_type discriminant (u8) — prevents cross-type hash collisions
        let tx_type_byte: u8 = match self.tx_type {
            TxType::Transfer       => 0x00,
            TxType::Confidential   => 0x01,
            TxType::ContractCreate => 0x02,
            TxType::ContractCall   => 0x03,
            TxType::AtomicSwap     => 0x04,
            TxType::MultiSig       => 0x05,
            TxType::TokenTransfer  => 0x06,
            TxType::SwapTx         => 0x07,
            TxType::DexOrder       => 0x08,
        };
        buf.push(tx_type_byte);

        // 2. is_coinbase flag (u8) — prevents coinbase/transfer confusion
        buf.push(if self.is_coinbase { 0x01 } else { 0x00 });

        // 3. timestamp (u64 LE)
        buf.extend_from_slice(&self.timestamp.to_le_bytes());

        // 4. fee (u64 LE)
        buf.extend_from_slice(&self.fee.to_le_bytes());

        // 3. inputs — sorted by (txid, index) for determinism
        let mut sorted_indices: Vec<usize> = (0..self.inputs.len()).collect();
        sorted_indices.sort_unstable_by(|&a, &b| {
            self.inputs[a].txid.cmp(&self.inputs[b].txid)
                .then(self.inputs[a].index.cmp(&self.inputs[b].index))
        });

        buf.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for &i in &sorted_indices {
            let inp = &self.inputs[i];
            // txid: length-prefixed string
            let txid_bytes = inp.txid.as_bytes();
            buf.extend_from_slice(&(txid_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(txid_bytes);
            // index: u32 LE
            buf.extend_from_slice(&inp.index.to_le_bytes());
            // owner: length-prefixed string — binds input to a specific owner address
            let owner_bytes = inp.owner.as_bytes();
            buf.extend_from_slice(&(owner_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(owner_bytes);
            // pub_key: length-prefixed string — binds to specific signing key
            // This prevents semantic mutation where an attacker changes the
            // pub_key without invalidating the tx hash.
            let pk_bytes = inp.pub_key.as_bytes();
            buf.extend_from_slice(&(pk_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(pk_bytes);

            // Privacy fields (if present)
            if let Some(ref ki) = inp.key_image {
                buf.push(0x01); // marker: has key_image
                let ki_bytes = ki.as_bytes();
                buf.extend_from_slice(&(ki_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(ki_bytes);
            } else {
                buf.push(0x00); // marker: no key_image
            }

            // ring_members: commit the decoy set to the txid so changing
            // ring members invalidates the hash (prevents decoy-set mutation).
            if let Some(ref members) = inp.ring_members {
                buf.push(0x01); // has ring_members
                buf.extend_from_slice(&(members.len() as u32).to_le_bytes());
                for m in members {
                    let m_bytes = m.as_bytes();
                    buf.extend_from_slice(&(m_bytes.len() as u32).to_le_bytes());
                    buf.extend_from_slice(m_bytes);
                }
            } else {
                buf.push(0x00);
            }
        }

        // 4. outputs — in original order (order matters for output indices)
        buf.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for out in &self.outputs {
            // address: length-prefixed string
            let addr_bytes = out.address.as_bytes();
            buf.extend_from_slice(&(addr_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(addr_bytes);
            // amount: u64 LE
            buf.extend_from_slice(&out.amount.to_le_bytes());

            // Privacy fields (if present)
            if let Some(ref c) = out.commitment {
                buf.push(0x01);
                buf.extend_from_slice(&(c.len() as u32).to_le_bytes());
                buf.extend_from_slice(c.as_bytes());
            } else {
                buf.push(0x00);
            }
            if let Some(ref rp) = out.range_proof {
                buf.push(0x01);
                buf.extend_from_slice(&(rp.len() as u32).to_le_bytes());
                buf.extend_from_slice(rp.as_bytes());
            } else {
                buf.push(0x00);
            }
            if let Some(ref epk) = out.ephemeral_pubkey {
                buf.push(0x01);
                buf.extend_from_slice(&(epk.len() as u32).to_le_bytes());
                buf.extend_from_slice(epk.as_bytes());
            } else {
                buf.push(0x00);
            }
        }

        // 5. payload_hash — chain-state binding (replay protection)
        // 0x00 = absent, 0x01 + length-prefixed hash = present
        match &self.payload_hash {
            Some(ph) => {
                buf.push(0x01);
                let ph_bytes = ph.as_bytes();
                buf.extend_from_slice(&(ph_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(ph_bytes);
            }
            None => {
                buf.push(0x00);
            }
        }

        // 6. gas_limit (contract TX field)
        match self.gas_limit {
            Some(gl) => {
                buf.push(0x01);
                buf.extend_from_slice(&gl.to_le_bytes());
            }
            None => {
                buf.push(0x00);
            }
        }

        // 7. deploy_code (ContractCreate bytecode)
        match &self.deploy_code {
            Some(code) => {
                buf.push(0x01);
                buf.extend_from_slice(&(code.len() as u32).to_le_bytes());
                buf.extend_from_slice(code);
            }
            None => {
                buf.push(0x00);
            }
        }

        // 8. calldata (ContractCall input data)
        match &self.calldata {
            Some(cd) => {
                buf.push(0x01);
                buf.extend_from_slice(&(cd.len() as u32).to_le_bytes());
                buf.extend_from_slice(cd);
            }
            None => {
                buf.push(0x00);
            }
        }

        // 9. contract_address (ContractCall target)
        match &self.contract_address {
            Some(ca) => {
                buf.push(0x01);
                let ca_bytes = ca.as_bytes();
                buf.extend_from_slice(&(ca_bytes.len() as u32).to_le_bytes());
                buf.extend_from_slice(ca_bytes);
            }
            None => {
                buf.push(0x00);
            }
        }

        // 10. vm_version
        match self.vm_version {
            Some(v) => {
                buf.push(0x01);
                buf.push(v);
            }
            None => {
                buf.push(0x00);
            }
        }

        buf
    }
}

impl TxInput {
    pub fn new(txid: String, index: u32, owner: String, signature: String, pub_key: String) -> Self {
        Self { txid, index, owner, signature, pub_key, key_image: None, ring_members: None }
    }

    /// Create a privacy input with key image and ring members
    pub fn new_confidential(
        txid: String, index: u32, owner: String,
        signature: String, pub_key: String,
        key_image: String, ring_members: Vec<String>,
    ) -> Self {
        Self { txid, index, owner, signature, pub_key, key_image: Some(key_image), ring_members: Some(ring_members) }
    }
}

impl TxOutput {
    /// Create a transparent output (plaintext amount)
    pub fn new(address: String, amount: u64) -> Self {
        Self { address, amount, commitment: None, range_proof: None, ephemeral_pubkey: None }
    }

    /// Create a confidential output (hidden amount with commitment + range proof)
    pub fn new_confidential(address: String, commitment: String, range_proof: String) -> Self {
        Self { address, amount: 0, commitment: Some(commitment), range_proof: Some(range_proof), ephemeral_pubkey: None }
    }

    /// Returns true if this output uses a Pedersen commitment
    pub fn is_confidential(&self) -> bool {
        self.commitment.is_some()
    }
}
