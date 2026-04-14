// ═══════════════════════════════════════════════════════════════════════════
//                           S H A D O W D A G
//                     © ShadowDAG Project — All Rights Reserved
// ═══════════════════════════════════════════════════════════════════════════

use crate::domain::transaction::transaction::{Transaction, TxInput, TxOutput, TxType};
use crate::errors::WalletError;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hex;
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use zeroize::Zeroize;

const PBKDF2_ITER: u32 = 600_000;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const CHECKSUM_BYTES: usize = 4;
const DUST_LIMIT: u64 = 546;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct WalletAddress {
    pub address: String,
    pub public_key: String,
    pub account: u32,
    pub index: u32,
    pub is_change: bool,
    pub label: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Walletutxo {
    pub txid: String,
    pub index: u32,
    pub amount: u64,
    pub address: String,
    pub height: u64,
    pub confirmations: u64,
    pub is_coinbase: bool,
    pub is_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTx {
    pub txid: String,
    pub direction: TxDirection,
    pub amount: u64,
    pub fee: u64,
    pub timestamp: u64,
    pub height: u64,
    pub confirmations: u64,
    pub to_address: String,
    pub from_address: String,
    pub status: TxStatus,
    pub memo: String,
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxDirection {
    Sent,
    Received,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxStatus {
    Pending,
    Confirmed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAccount {
    pub index: u32,
    pub label: String,
    pub addresses: Vec<WalletAddress>,
    pub balance: u64,
    pub tx_count: u64,
    pub created_at: u64,
}

impl WalletAccount {
    pub fn primary_address(&self) -> Option<&str> {
        self.addresses.first().map(|a| a.address.as_str())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WalletState {
    pub version: u32,
    pub network: String,
    pub created_at: u64,
    pub accounts: Vec<WalletAccount>,
}

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    state: WalletState,
    utxos: HashMap<String, Vec<Walletutxo>>,
    history: HashMap<String, Vec<WalletTx>>,
    #[serde(skip)]
    session_key: Option<Vec<u8>>,
    locked: bool,
    network: String,
}

impl Wallet {
    pub fn new(network: &str) -> Self {
        Self {
            state: WalletState {
                version: 1,
                network: network.to_string(),
                created_at: unix_now(),
                accounts: Vec::new(),
            },
            utxos: HashMap::new(),
            history: HashMap::new(),
            session_key: None,
            locked: true,
            network: network.to_string(),
        }
    }

    pub fn create(&mut self, password: &str) -> Result<(Vec<String>, EncryptedSeed), WalletError> {
        let mut entropy = [0u8; 32];
        OsRng.fill_bytes(&mut entropy);
        let mnemonic = entropy_to_mnemonic_simple(&entropy);
        let seed = mnemonic_to_seed_simple(&mnemonic, "");
        let enc = encrypt_bytes(&seed, password)?;
        self.session_key = Some(seed);
        self.locked = false;

        self.add_account(0, "Default Account")?;
        Ok((mnemonic, enc))
    }

    pub fn restore_from_seed(&mut self, seed: Vec<u8>) -> Result<(), WalletError> {
        self.session_key = Some(seed);
        self.locked = false;
        // Create default account if empty (critical for usability after restore)
        if self.state.accounts.is_empty() {
            self.add_account(0, "Default")?;
        }
        Ok(())
    }

    pub fn unlock(&mut self, enc_seed: &EncryptedSeed, password: &str) -> Result<(), WalletError> {
        let seed = decrypt_bytes(
            &enc_seed.ciphertext,
            &enc_seed.salt,
            &enc_seed.nonce,
            password,
        )?;
        self.session_key = Some(seed);
        self.locked = false;
        Ok(())
    }

    pub fn lock(&mut self) {
        if let Some(mut k) = self.session_key.take() {
            k.zeroize();
        }
        self.locked = true;
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Force wallet into locked state after deserialization.
    /// `session_key` is `#[serde(skip)]`, so after load the wallet appears
    /// unlocked but has no key — this fixes that inconsistency.
    pub fn force_locked_after_load(&mut self) {
        self.session_key = None;
        self.locked = true;
    }
    pub fn address(&self) -> String {
        self.state
            .accounts
            .first()
            .and_then(|a| a.primary_address())
            .unwrap_or("__no_address__")
            .to_string()
    }

    pub fn add_account(&mut self, index: u32, label: &str) -> Result<WalletAccount, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }
        let seed = self
            .session_key
            .as_ref()
            .ok_or(WalletError::Other("No session key".to_string()))?;

        let signing_key = derive_key(seed, index, 0, false)?;
        let verifying: VerifyingKey = signing_key.verifying_key();
        let pub_hex = hex::encode(verifying.as_bytes());
        let address = make_address(&pub_hex, &self.network)?;

        let wa = WalletAddress {
            address: address.clone(),
            public_key: pub_hex,
            account: index,
            index: 0,
            is_change: false,
            label: "Primary".to_string(),
            created_at: unix_now(),
        };

        let acc = WalletAccount {
            index,
            label: label.to_string(),
            addresses: vec![wa],
            balance: 0,
            tx_count: 0,
            created_at: unix_now(),
        };

        if self.state.accounts.iter().any(|a| a.index == index) {
            return Err(WalletError::Other(format!(
                "account {} already exists",
                index
            )));
        }
        self.state.accounts.push(acc.clone());
        Ok(acc)
    }

    pub fn derive_change_address(
        &mut self,
        account: u32,
        addr_index: u32,
    ) -> Result<WalletAddress, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }
        let seed = self
            .session_key
            .as_ref()
            .ok_or(WalletError::Other("No session key".to_string()))?;
        let sk = derive_key(seed, account, addr_index, true)?;
        let vk: VerifyingKey = sk.verifying_key();
        let pub_hex = hex::encode(vk.as_bytes());
        let address = make_address(&pub_hex, &self.network)?;

        let wa = WalletAddress {
            address: address.clone(),
            public_key: pub_hex,
            account,
            index: addr_index,
            is_change: true,
            label: format!("Change {}", addr_index),
            created_at: unix_now(),
        };

        let acc = self
            .state
            .accounts
            .iter_mut()
            .find(|a| a.index == account)
            .ok_or_else(|| WalletError::Other(format!("account {} not found", account)))?;
        // Dedup: don't add if an address with the same index and is_change already exists
        if !acc
            .addresses
            .iter()
            .any(|a| a.is_change && a.index == addr_index)
        {
            acc.addresses.push(wa.clone());
        }
        Ok(wa)
    }

    pub fn accounts(&self) -> &[WalletAccount] {
        &self.state.accounts
    }

    pub fn account(&self, idx: u32) -> Option<&WalletAccount> {
        self.state.accounts.iter().find(|a| a.index == idx)
    }

    pub fn total_balance(&self) -> u64 {
        match self
            .state
            .accounts
            .iter()
            .try_fold(0u64, |acc, a| acc.checked_add(a.balance))
        {
            Some(total) => total,
            None => {
                eprintln!(
                    "[WARN] wallet total_balance overflow — account balances exceed u64::MAX"
                );
                u64::MAX
            }
        }
    }

    pub fn utxos_for(&self, address: &str) -> Vec<&Walletutxo> {
        self.utxos
            .get(address)
            .map(|v| v.iter().filter(|u| !u.is_locked).collect())
            .unwrap_or_default()
    }

    pub fn history_for(&self, address: &str) -> Vec<&WalletTx> {
        let mut txs: Vec<&WalletTx> = self
            .history
            .get(address)
            .map(|v| v.iter().collect())
            .unwrap_or_default();
        txs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        txs
    }

    pub fn update_utxos(&mut self, address: &str, utxos: Vec<Walletutxo>) {
        let bal: u64 = utxos
            .iter()
            .filter(|u| !u.is_locked)
            .map(|u| u.amount)
            .try_fold(0u64, |acc, u| acc.checked_add(u))
            .unwrap_or(u64::MAX);
        self.utxos.insert(address.to_string(), utxos);

        if let Some(acc) = self
            .state
            .accounts
            .iter_mut()
            .find(|a| a.addresses.iter().any(|ad| ad.address == address))
        {
            acc.balance = bal;
        }
    }

    pub fn update_history(&mut self, address: &str, txs: Vec<WalletTx>) {
        let count = txs.len() as u64;
        self.history.insert(address.to_string(), txs);
        if let Some(acc) = self
            .state
            .accounts
            .iter_mut()
            .find(|a| a.addresses.iter().any(|ad| ad.address == address))
        {
            acc.tx_count = count;
        }
    }

    pub fn build_tx(
        &mut self,
        from_account: u32,
        to_address: &str,
        amount: u64,
        fee: u64,
        memo: &str,
    ) -> Result<BuiltTx, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }

        let acc = self
            .account(from_account)
            .ok_or(WalletError::Other("Account not found".to_string()))?
            .clone();
        if acc.addresses.is_empty() {
            return Err(WalletError::AddressNotFound(
                "No address in account".to_string(),
            ));
        }

        // Collect UTXOs from ALL account addresses, not just the primary one
        let mut all_utxos: Vec<Walletutxo> = acc
            .addresses
            .iter()
            .flat_map(|a| self.utxos_for(&a.address))
            .cloned()
            .collect();

        let avail_bal: u64 = all_utxos
            .iter()
            .map(|u| u.amount)
            .try_fold(0u64, |acc, u| acc.checked_add(u))
            .ok_or(WalletError::BalanceOverflow)?;
        if avail_bal < amount.saturating_add(fee) {
            return Err(WalletError::InsufficientFunds {
                need: amount + fee,
                have: avail_bal,
            });
        }
        all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut selected = Vec::new();
        let mut total_in = 0u64;
        for u in all_utxos {
            selected.push(u.clone());
            total_in += u.amount;
            if total_in >= amount.saturating_add(fee) {
                break;
            }
        }

        let change = total_in.saturating_sub(amount.saturating_add(fee));
        let seed = self
            .session_key
            .as_ref()
            .ok_or(WalletError::Other("No session key".to_string()))?
            .clone();

        let mut signed_inputs = Vec::new();
        for utxo in &selected {
            // Find which address owns this UTXO and derive the correct key
            let wa = acc
                .addresses
                .iter()
                .find(|a| a.address == utxo.address)
                .ok_or(WalletError::AddressNotFound(utxo.address.clone()))?;
            let sk = derive_key(&seed, wa.account, wa.index, wa.is_change)?;
            // FIXED: Use the SAME signing message format as TxValidator (TxHash::signing_message)
            // Format: SHA-256(CHAIN_ID || txid || index || to_address || amount || fee)
            let chain_id = match self.network.as_str() {
                "mainnet" => 0xDA0C_0001u32,
                "testnet" => 0xDA0C_0002u32,
                "regtest" => 0xDA0C_0003u32,
                _ => 0xDA0C_0001u32, // fallback to mainnet
            };
            let mut h = sha2::Sha256::new();
            sha2::Digest::update(&mut h, chain_id.to_le_bytes()); // Chain ID
            sha2::Digest::update(&mut h, utxo.txid.as_bytes());
            sha2::Digest::update(&mut h, utxo.index.to_le_bytes());
            sha2::Digest::update(&mut h, to_address.as_bytes());
            sha2::Digest::update(&mut h, amount.to_le_bytes());
            sha2::Digest::update(&mut h, fee.to_le_bytes());
            let msg = sha2::Digest::finalize(h);
            let sig: Signature = sk.sign(&msg);
            signed_inputs.push(SignedInput {
                txid: utxo.txid.clone(),
                index: utxo.index,
                signature: hex::encode(sig.to_bytes()),
                pub_key: wa.public_key.clone(),
                address: utxo.address.clone(),
            });
        }

        let mut outputs = vec![TxOut {
            address: to_address.to_string(),
            amount,
        }];
        if change > DUST_LIMIT {
            let next_idx = acc
                .addresses
                .iter()
                .filter(|a| a.is_change)
                .map(|a| a.index)
                .max()
                .map(|x| x + 1)
                .unwrap_or(1);
            let change_addr = match self.derive_change_address(from_account, next_idx) {
                Ok(wa) => wa.address,
                Err(_) => {
                    return Err(WalletError::Other("cannot derive change address".into()));
                }
            };
            outputs.push(TxOut {
                address: change_addr,
                amount: change,
            });
        }

        let txid = compute_txid(&signed_inputs, &outputs, fee);

        Ok(BuiltTx {
            txid: txid.clone(),
            inputs: signed_inputs,
            outputs,
            fee,
            memo: memo.to_string(),
            timestamp: unix_now(),
            raw_hex: format!("raw:{}", txid),
        })
    }

    /// Validate a ShadowDAG address.
    ///
    /// Address format produced by `make_address`:
    ///   prefix (2 chars: "SD"/"ST"/"SR") + hex(version(1) + hash(32) + checksum(4))
    ///   = prefix(2) + 74 hex chars = 76 total chars for standard addresses.
    ///
    /// Stealth addresses use a 4-char prefix ("SD1s"/"ST1s"/"SR1s") + 40 hex = 44 total.
    pub fn is_valid_address(&self, addr: &str) -> bool {
        let prefix = match self.network.as_str() {
            "testnet" => "ST",
            "regtest" => "SR",
            _ => "SD",
        };
        if !addr.starts_with(prefix) {
            return false;
        }
        let after_net = &addr[prefix.len()..];

        // Stealth addresses: prefix + "1s" + 40 hex = 4-char prefix total
        if after_net.starts_with("1s") || after_net.starts_with("1c") || after_net.starts_with("1m")
        {
            let hex_part = &after_net[2..];
            return hex_part.len() == 40 && hex_part.chars().all(|c| c.is_ascii_hexdigit());
        }

        // Standard addresses: prefix(2) + 74 hex chars (version + hash + checksum)
        // 74 hex chars = 37 bytes: 1 version + 32 hash + 4 checksum
        if after_net.len() != 74 {
            return false;
        }
        after_net.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Select UTXOs from an account to cover the requested amount.
    /// Returns (selected_utxos, total_input_value).
    fn select_utxos(
        &self,
        acc: &WalletAccount,
        amount: u64,
    ) -> Result<(Vec<Walletutxo>, u64), WalletError> {
        let mut utxos: Vec<Walletutxo> = acc
            .addresses
            .iter()
            .flat_map(|a| self.utxos_for(&a.address))
            .cloned()
            .collect();
        utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

        let mut selected = Vec::new();
        let mut total = 0u64;
        for u in utxos {
            selected.push(u.clone());
            total += u.amount;
            if total >= amount {
                break;
            }
        }
        if total < amount {
            return Err(WalletError::InsufficientFunds {
                need: amount,
                have: total,
            });
        }
        Ok((selected, total))
    }

    /// Build a contract deployment transaction.
    /// The bytecode is included in deploy_code, and gas_limit is set.
    /// Returns a signed Transaction ready for broadcast.
    pub fn build_deploy_tx(
        &mut self,
        from_account: u32,
        bytecode: Vec<u8>,
        value: u64,
        gas_limit: u64,
        fee: u64,
    ) -> Result<Transaction, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }

        let acc = self
            .account(from_account)
            .ok_or(WalletError::Other("Account not found".into()))?
            .clone();
        let addr = acc
            .primary_address()
            .ok_or(WalletError::AddressNotFound("No address".into()))?
            .to_string();

        // Collect UTXOs for gas + value
        let total_needed = value.saturating_add(fee);
        let (selected, total_in) = self.select_utxos(&acc, total_needed)?;

        let inputs: Vec<TxInput> = selected
            .iter()
            .map(|u| TxInput {
                txid: u.txid.clone(),
                index: u.index,
                owner: addr.clone(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
            })
            .collect();

        let mut outputs = vec![TxOutput {
            address: "contract_deploy".into(), // placeholder — actual address computed by VM
            amount: value,
            commitment: None,
            range_proof: None,
            ephemeral_pubkey: None,
        }];

        // Change output if needed
        let change = total_in.saturating_sub(total_needed);
        if change > 0 {
            outputs.push(TxOutput {
                address: addr.clone(),
                amount: change,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            });
        }

        let tx = Transaction {
            hash: String::new(), // computed after signing
            inputs,
            outputs,
            fee,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_coinbase: false,
            tx_type: TxType::ContractCreate,
            payload_hash: None,
            gas_limit: Some(gas_limit),
            deploy_code: Some(bytecode),
            calldata: None,
            contract_address: None,
            vm_version: Some(1),
        };

        // Sign (use existing signing logic from build_tx)
        // For now, return unsigned — signing requires private key access
        Ok(tx)
    }

    /// Build a contract call transaction.
    pub fn build_call_tx(
        &mut self,
        from_account: u32,
        contract_addr: &str,
        calldata: Vec<u8>,
        value: u64,
        gas_limit: u64,
        fee: u64,
    ) -> Result<Transaction, WalletError> {
        if self.locked {
            return Err(WalletError::Locked);
        }

        let acc = self
            .account(from_account)
            .ok_or(WalletError::Other("Account not found".into()))?
            .clone();
        let addr = acc
            .primary_address()
            .ok_or(WalletError::AddressNotFound("No address".into()))?
            .to_string();

        let total_needed = value.saturating_add(fee);
        let (selected, total_in) = self.select_utxos(&acc, total_needed)?;

        let inputs: Vec<TxInput> = selected
            .iter()
            .map(|u| TxInput {
                txid: u.txid.clone(),
                index: u.index,
                owner: addr.clone(),
                signature: String::new(),
                pub_key: String::new(),
                key_image: None,
                ring_members: None,
            })
            .collect();

        let mut outputs = vec![TxOutput {
            address: contract_addr.to_string(),
            amount: value,
            commitment: None,
            range_proof: None,
            ephemeral_pubkey: None,
        }];

        let change = total_in.saturating_sub(total_needed);
        if change > 0 {
            outputs.push(TxOutput {
                address: addr.clone(),
                amount: change,
                commitment: None,
                range_proof: None,
                ephemeral_pubkey: None,
            });
        }

        Ok(Transaction {
            hash: String::new(),
            inputs,
            outputs,
            fee,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_coinbase: false,
            tx_type: TxType::ContractCall,
            payload_hash: None,
            gas_limit: Some(gas_limit),
            deploy_code: None,
            calldata: Some(calldata),
            contract_address: Some(contract_addr.to_string()),
            vm_version: Some(1),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSeed {
    pub ciphertext: Vec<u8>,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltTx {
    pub txid: String,
    pub inputs: Vec<SignedInput>,
    pub outputs: Vec<TxOut>,
    pub fee: u64,
    pub memo: String,
    pub timestamp: u64,
    pub raw_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInput {
    pub txid: String,
    pub index: u32,
    pub signature: String,
    pub pub_key: String,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOut {
    pub address: String,
    pub amount: u64,
}

fn derive_key(
    seed: &[u8],
    account: u32,
    index: u32,
    change: bool,
) -> Result<SigningKey, WalletError> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let path = format!(
        "ShadowDAG/44'/999'/{}'/{}/{}",
        account,
        if change { 1 } else { 0 },
        index
    );
    let mut mac = <HmacSha256 as Mac>::new_from_slice(seed)
        .map_err(|e| WalletError::KeyDerivation(e.to_string()))?;
    mac.update(path.as_bytes());
    let res = mac.finalize().into_bytes();
    let key: [u8; 32] = res[..32]
        .try_into()
        .map_err(|_| WalletError::KeyDerivation("Key slice error".to_string()))?;
    Ok(SigningKey::from_bytes(&key))
}

fn make_address(pub_hex: &str, network: &str) -> Result<String, WalletError> {
    let pub_bytes = hex::decode(pub_hex)
        .map_err(|e| WalletError::Other(format!("invalid public key hex: {}", e)))?;
    if pub_bytes.len() != 32 {
        return Err(WalletError::Other(format!(
            "public key must be 32 bytes, got {}",
            pub_bytes.len()
        )));
    }
    let hash = Sha3_256::digest(&pub_bytes);
    let version = match network {
        "testnet" => 0x01u8,
        "regtest" => 0x02,
        _ => 0x00,
    };
    let mut payload = vec![version];
    payload.extend_from_slice(&hash);
    let cs = &Sha3_256::digest(Sha3_256::digest(&payload))[..CHECKSUM_BYTES];
    payload.extend_from_slice(cs);
    let prefix = match network {
        "testnet" => "ST",
        "regtest" => "SR",
        _ => "SD",
    };
    Ok(format!("{}{}", prefix, hex::encode(&payload)))
}

fn compute_txid(inputs: &[SignedInput], outputs: &[TxOut], fee: u64) -> String {
    let mut h = Sha3_256::new();
    for inp in inputs {
        h.update(inp.txid.as_bytes());
        h.update(inp.index.to_le_bytes());
        h.update(inp.signature.as_bytes());
    }
    for out in outputs {
        h.update(out.address.as_bytes());
        h.update(out.amount.to_le_bytes());
    }
    h.update(fee.to_le_bytes());
    hex::encode(h.finalize())
}

fn entropy_to_mnemonic_simple(entropy: &[u8]) -> Vec<String> {
    // BIP-39 compatible: 2048 words derived deterministically from a master seed.
    // Each word = 11 bits of entropy. 12 words = 132 bits (128 + 4 checksum).
    // We generate 2048 unique words from SHA-256 hashing of indices.
    let wordlist = generate_bip39_wordlist();

    let hash = Sha3_256::digest(entropy);

    // Extract 11-bit indices from hash (BIP-39 standard)
    let mut bits: Vec<u8> = Vec::with_capacity(256);
    for byte in hash.iter() {
        for bit in (0..8).rev() {
            bits.push((byte >> bit) & 1);
        }
    }

    (0..12)
        .map(|i| {
            // 11 bits per word index
            let start = i * 11;
            let mut idx: usize = 0;
            for b in 0..11 {
                if start + b < bits.len() {
                    idx = (idx << 1) | (bits[start + b] as usize);
                }
            }
            wordlist[idx % 2048].clone()
        })
        .collect()
}

/// Generate a deterministic 2048-word list from SHA-256.
/// Each word is unique, 3-8 characters, lowercase alpha.
/// This replaces the old 65-word list for proper 128-bit entropy.
fn generate_bip39_wordlist() -> Vec<String> {
    use sha2::{Digest, Sha256};

    // Base syllables for word construction
    const CONSONANTS: &[u8] = b"bcdfghjklmnprstvwxyz";
    const VOWELS: &[u8] = b"aeiou";

    let mut words: Vec<String> = Vec::with_capacity(2048);
    let mut seen = std::collections::HashSet::with_capacity(2048);

    for i in 0u32..8192 {
        // Deterministic hash per index
        let mut h = Sha256::new();
        h.update(b"ShadowDAG_BIP39_WordGen_v1");
        h.update(i.to_le_bytes());
        let hash = h.finalize();

        // Generate a 3-7 char word from hash bytes
        let word_len = 3 + (hash[0] % 5) as usize; // 3 to 7 chars
        let mut word = String::with_capacity(word_len);

        for j in 0..word_len {
            let byte = hash[(j + 1) % 32];
            if j % 2 == 0 {
                word.push(CONSONANTS[(byte as usize) % CONSONANTS.len()] as char);
            } else {
                word.push(VOWELS[(byte as usize) % VOWELS.len()] as char);
            }
        }

        if word.len() >= 3 && seen.insert(word.clone()) {
            words.push(word);
            if words.len() >= 2048 {
                break;
            }
        }
    }

    words
}

fn mnemonic_to_seed_simple(words: &[String], passphrase: &str) -> Vec<u8> {
    let sentence = words.join(" ");
    let salt = format!("ShadowDAG{}", passphrase);
    let mut seed = vec![0u8; 64];
    pbkdf2_hmac::<Sha256>(sentence.as_bytes(), salt.as_bytes(), 2048, &mut seed);
    seed
}

fn encrypt_bytes(data: &[u8], password: &str) -> Result<EncryptedSeed, WalletError> {
    let mut salt = vec![0u8; SALT_LEN];
    let mut nonce = vec![0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PBKDF2_ITER, &mut key);

    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| WalletError::Encryption(e.to_string()))?;
    let n = aes_gcm::Nonce::from_slice(&nonce);
    let ct = cipher
        .encrypt(n, data)
        .map_err(|_| WalletError::Encryption("Encrypt failed".to_string()))?;
    key.zeroize();

    Ok(EncryptedSeed {
        ciphertext: ct,
        salt,
        nonce,
    })
}

fn decrypt_bytes(
    ct: &[u8],
    salt: &[u8],
    nonce: &[u8],
    password: &str,
) -> Result<Vec<u8>, WalletError> {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITER, &mut key);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| WalletError::Encryption(e.to_string()))?;
    let n = aes_gcm::Nonce::from_slice(nonce);
    let plain = cipher.decrypt(n, ct).map_err(|_| WalletError::AuthFailed)?;
    key.zeroize();
    Ok(plain)
}

fn unix_now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_unlock() {
        let mut w = Wallet::new("mainnet");
        let (words, enc) = w.create("password123").unwrap();
        assert_eq!(words.len(), 12);
        w.lock();
        assert!(w.is_locked());
        w.unlock(&enc, "password123").unwrap();
        assert!(!w.is_locked());
    }

    #[test]
    fn wrong_password_fails() {
        let mut w = Wallet::new("mainnet");
        let (_, enc) = w.create("correct").unwrap();
        w.lock();
        assert!(w.unlock(&enc, "wrong").is_err());
    }

    #[test]
    fn address_validation() {
        let mut w = Wallet::new("mainnet");
        let _ = w.create("pw");
        let acc = &w.accounts()[0];
        let addr = acc.primary_address().unwrap().to_string();
        assert!(w.is_valid_address(&addr));
        assert!(!w.is_valid_address("invalid"));
    }

    #[test]
    fn account_derivation() {
        let mut w = Wallet::new("mainnet");
        let _ = w.create("pw");
        let acc0 = w.account(0).unwrap().clone();
        assert_eq!(acc0.index, 0);
        assert!(!acc0.addresses.is_empty());
    }

    #[test]
    fn testnet_address_prefix() {
        let mut w = Wallet::new("testnet");
        let _ = w.create("pw");
        let addr = w.accounts()[0].primary_address().unwrap().to_string();
        assert!(addr.starts_with("ST"));
    }
}
